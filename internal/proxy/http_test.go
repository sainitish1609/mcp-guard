package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sainitish1609/mcp-guard/internal/audit"
	"github.com/sainitish1609/mcp-guard/internal/config"
)

// newHTTPHandler wires a handler against a mock upstream for testing.
func newHTTPHandler(t *testing.T, upstream string) *httpHandler {
	t.Helper()
	cfg := config.Default()
	cfg.Stats = false
	cfg.ExpandPaths()
	return &httpHandler{
		p:        newPipeline(cfg, audit.New(config.LogSilent, false)),
		upstream: strings.TrimRight(upstream, "/"),
		client:   &http.Client{},
	}
}

func TestHTTPRedactsJSONResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"k AKIAIOSFODNN7EXAMPLE"}]}}`)
	}))
	defer upstream.Close()

	h := newHTTPHandler(t, upstream.URL)
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"x"}}}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret leaked through HTTP proxy: %s", body)
	}
	if !strings.Contains(body, "[REDACTED:aws-access-key]") {
		t.Fatalf("expected mask, got %s", body)
	}
}

func TestHTTPBlocksProtectedWriteWithoutUpstream(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer upstream.Close()

	h := newHTTPHandler(t, upstream.URL)
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.ssh/authorized_keys","content":"x"}}}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if hit {
		t.Fatal("blocked write must not reach upstream")
	}
	if !strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Fatalf("expected isError block response, got %s", rec.Body.String())
	}
}

func TestHTTPTransformsSSEStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "event: message\n")
		io.WriteString(w, `data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"k AKIAIOSFODNN7EXAMPLE"}]}}`+"\n")
		io.WriteString(w, "\n")
	}))
	defer upstream.Close()

	h := newHTTPHandler(t, upstream.URL)
	req := httptest.NewRequest("GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret leaked through SSE proxy: %s", body)
	}
	if !strings.Contains(body, "[REDACTED:aws-access-key]") {
		t.Fatalf("expected mask in SSE data, got %s", body)
	}
	if !strings.Contains(body, "data:") {
		t.Fatalf("SSE framing lost: %s", body)
	}
}

// RunHTTP should refuse to start without an upstream.
func TestRunHTTPRequiresUpstream(t *testing.T) {
	err := RunHTTP(context.Background(), config.Default(), audit.New(config.LogSilent, false), ":0", "", nil)
	if err == nil {
		t.Fatal("expected error when upstream is empty")
	}
}
