package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sainitish1609/mcp-guard/internal/audit"
	"github.com/sainitish1609/mcp-guard/internal/config"
)

// RunHTTP starts an HTTP proxy in front of a remote MCP server that speaks the
// Streamable-HTTP transport (JSON and Server-Sent-Events). It applies the exact
// same guard/redact/inject/anomaly pipeline as the stdio proxy, so remote MCP
// servers get the same protection as local ones.
//
// listen is the local address to bind (e.g. ":8080"); upstream is the remote
// MCP endpoint URL. The call blocks until ctx is cancelled.
func RunHTTP(ctx context.Context, cfg config.Config, log *audit.Logger, listen, upstream string, reload func() (config.Config, error)) error {
	if upstream == "" {
		return errors.New("http mode requires an upstream URL")
	}
	p := newPipeline(cfg, log)
	p.reload = reload

	if cfg.Stats {
		defer p.printSummary()
	}
	defer p.installSignals(ctx, cfg.Stats)()

	h := &httpHandler{p: p, upstream: strings.TrimRight(upstream, "/"), client: &http.Client{}}
	srv := &http.Server{Addr: listen, Handler: h}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Startup("http-proxy listen=" + listen + " upstream=" + upstream)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type httpHandler struct {
	p        *Proxy
	upstream string
	client   *http.Client
}

// hopByHop headers are connection-specific and must not be forwarded.
var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true, "Content-Length": true,
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	// Apply the request pipeline to a single JSON-RPC object. A blocked tools/call
	// is answered locally with an isError result and never reaches upstream.
	forward := body
	if len(body) > 0 && looksLikeJSONObject(body) {
		fwd, block := h.p.evaluateRequest(body)
		if block != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.TrimRight(block, "\n"))
			return
		}
		forward = fwd
	}

	// Build the upstream request, preserving method and relevant headers.
	target := h.upstream + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(forward))
	if err != nil {
		http.Error(w, "mcp-guard: bad upstream request", http.StatusBadGateway)
		return
	}
	copyHeaders(req.Header, r.Header)

	resp, err := h.client.Do(req)
	if err != nil {
		http.Error(w, "mcp-guard: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		w.WriteHeader(resp.StatusCode)
		h.streamSSE(w, resp.Body)
		return
	}

	// Non-streaming JSON response: transform the whole body.
	data, _ := io.ReadAll(resp.Body)
	if looksLikeJSONObject(data) {
		data = bytes.TrimRight(h.p.transformResponse(data), "\n")
	}
	w.Header().Set("Content-Length", itoa(len(data)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data)
}

// streamSSE reads an SSE stream, transforms the JSON in each `data:` event, and
// re-emits it, flushing after every event so streaming latency is preserved.
func (h *httpHandler) streamSSE(w http.ResponseWriter, body io.Reader) {
	flusher, _ := w.(http.Flusher)
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if data, ok := strings.CutPrefix(line, "data:"); ok {
			payload := strings.TrimSpace(data)
			if looksLikeJSONObject([]byte(payload)) {
				payload = string(bytes.TrimRight(h.p.transformResponse([]byte(payload)), "\n"))
			}
			_, _ = io.WriteString(w, "data: "+payload+"\n")
		} else {
			_, _ = io.WriteString(w, line+"\n")
		}
		if line == "" && flusher != nil {
			flusher.Flush() // event boundary
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// looksLikeJSONObject reports whether b begins with '{' after leading space.
func looksLikeJSONObject(b []byte) bool {
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && b[0] == '{'
}

// itoa is a tiny int→string without importing strconv at call sites.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
