// Package proxy is the core of mcp-guard: it launches the real MCP server as a
// child process and pumps the newline-delimited JSON-RPC stream in both
// directions, applying guard policy on the way out (client → server) and
// redaction, compression, and annotation on the way back (server → client).
package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sainitish1609/mcp-guard/internal/audit"
	"github.com/sainitish1609/mcp-guard/internal/compress"
	"github.com/sainitish1609/mcp-guard/internal/config"
	"github.com/sainitish1609/mcp-guard/internal/guard"
	"github.com/sainitish1609/mcp-guard/internal/jsonrpc"
	"github.com/sainitish1609/mcp-guard/internal/redact"
)

// bufSize is the initial read buffer; ReadBytes grows without limit so large
// results (file contents, DB schemas) are never truncated.
const bufSize = 64 * 1024

// Proxy holds the wired-up transformation pipeline and shared cross-goroutine
// state (the client stdout writer and the request→tool correlation map).
type Proxy struct {
	cfg      config.Config
	log      *audit.Logger
	guard    *guard.Guard
	redactor *redact.Engine

	clientMu sync.Mutex // serializes all writes to the client (stdout)
	client   io.Writer

	pendingMu sync.Mutex
	pending   map[string]string // request id -> tool name, for result correlation
}

// Run launches childCmd and proxies stdin/stdout through the guard pipeline until
// the child exits or ctx is cancelled. It returns the child's exit code.
func Run(ctx context.Context, cfg config.Config, log *audit.Logger, childCmd []string) (int, error) {
	if len(childCmd) == 0 {
		return 1, errors.New("no child command provided")
	}

	p := &Proxy{
		cfg:      cfg,
		log:      log,
		guard:    guard.New(cfg),
		redactor: redact.New(cfg.CustomPatterns),
		client:   os.Stdout,
		pending:  make(map[string]string),
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, childCmd[0], childCmd[1:]...)
	cmd.Stderr = os.Stderr // child's own logs pass straight through

	childIn, err := cmd.StdinPipe()
	if err != nil {
		return 1, err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1, err
	}

	if err := cmd.Start(); err != nil {
		return 1, err
	}

	// Forward termination signals to the child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case s := <-sigCh:
			if cmd.Process != nil {
				_ = cmd.Process.Signal(s)
			}
		case <-ctx.Done():
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// client → server: apply guard to tools/call requests.
	go func() {
		defer wg.Done()
		defer childIn.Close()
		p.pumpClientToServer(os.Stdin, childIn)
	}()

	// server → client: apply redaction, compression, annotation to results.
	go func() {
		defer wg.Done()
		p.pumpServerToClient(childOut)
	}()

	wg.Wait()
	err = cmd.Wait()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

// writeClient serializes writes to the client stream across both pumps.
func (p *Proxy) writeClient(b []byte) error {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()
	_, err := p.client.Write(b)
	return err
}

// rememberTool records a request id → tool-name mapping for later result
// correlation. id is the raw JSON bytes of the request id.
func (p *Proxy) rememberTool(id []byte, tool string) {
	if tool == "" || len(id) == 0 {
		return
	}
	p.pendingMu.Lock()
	p.pending[string(id)] = tool
	p.pendingMu.Unlock()
}

// takeTool returns and removes the tool name recorded for a response id.
func (p *Proxy) takeTool(id []byte) string {
	if len(id) == 0 {
		return ""
	}
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	tool := p.pending[string(id)]
	delete(p.pending, string(id))
	return tool
}

// pumpClientToServer reads client messages, applies guard policy, and forwards
// allowed messages to the child. Blocked tools/call requests are answered with
// an isError result written back to the client and never reach the child.
func (p *Proxy) pumpClientToServer(clientIn io.Reader, serverIn io.Writer) {
	reader := newLineReader(clientIn)
	for {
		line, err := reader.readLine()
		if len(line) > 0 {
			out := p.transformRequest(line)
			if out != nil {
				if _, werr := serverIn.Write(out); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// transformRequest inspects a client→server line. It returns the bytes to
// forward to the child, or nil if the request was blocked (in which case an
// isError response has already been written back to the client).
func (p *Proxy) transformRequest(line []byte) []byte {
	msg, err := jsonrpc.Parse(dropNewline(line))
	if err != nil || !msg.IsToolCall() {
		return line // pass through untouched
	}

	tool := msg.ToolName()
	p.rememberTool(msg.ID, tool)

	blocked, reason := p.guard.Inspect(tool, msg.ToolArgs())
	if !blocked {
		return line
	}

	p.log.Blocked(tool, reason)
	if p.cfg.DryRun {
		return line // dry-run: log only, still forward
	}

	// Blocked: the child never sees this call and never produces a result for
	// this id, so drop the pending correlation we just recorded.
	p.takeTool(msg.ID)

	resp := jsonrpc.NewToolErrorResult(msg.ID, "Blocked by mcp-guard: "+reason)
	if encoded, err := resp.Encode(); err == nil {
		_ = p.writeClient(append(encoded, '\n'))
	}
	return nil
}

// pumpServerToClient reads server messages, applies redaction/compression to
// results and annotation to tools/list, then forwards them to the client.
func (p *Proxy) pumpServerToClient(serverOut io.Reader) {
	reader := newLineReader(serverOut)
	for {
		line, err := reader.readLine()
		if len(line) > 0 {
			out := p.transformResponse(line)
			if werr := p.writeClient(out); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// transformResponse applies the server→client pipeline and returns the bytes to
// forward (with a trailing newline preserved).
func (p *Proxy) transformResponse(line []byte) []byte {
	body := dropNewline(line)
	msg, err := jsonrpc.Parse(body)
	if err != nil || len(msg.Result) == 0 {
		if err == nil {
			// A response with no result (e.g. an error) still clears any pending
			// correlation so the map does not grow unbounded.
			p.takeTool(msg.ID)
		}
		return line
	}

	tool := p.takeTool(msg.ID)
	changed := false

	// tools/list annotation.
	if p.cfg.AnnotateTools {
		if msg.MapToolListDescriptions(p.guard.Annotate) {
			changed = true
		}
	}

	// Redaction scans every string in the result (not just content[].text) so a
	// secret is masked even if the server mirrors it into structuredContent or
	// another field.
	if p.cfg.RedactSecrets {
		var hits []redact.Hit
		if msg.MapResultStrings(func(t string) string {
			masked, h := p.redactor.Scan(t)
			hits = append(hits, h...)
			return masked
		}) {
			changed = true
		}
		if len(hits) > 0 {
			p.log.Redacted(tool, redact.Summary(hits))
		}
	}

	// Compression (opt-in). Skip results from tools the agent edits round-trip.
	if p.cfg.Compress && !compress.SkipTool(tool) {
		var totBefore, totAfter int
		var truncatedAny bool
		if msg.MapResultText(func(t string) string {
			out, r := compress.Text(t, p.cfg.MaxTokens)
			totBefore += r.BytesBefore
			totAfter += r.BytesAfter
			truncatedAny = truncatedAny || r.Truncated
			return out
		}) {
			changed = true
			p.log.Compressed(tool, totBefore, totAfter, truncatedAny)
		}
	}

	if !changed || p.cfg.DryRun {
		return line
	}
	if encoded, err := msg.Encode(); err == nil {
		return append(encoded, '\n')
	}
	return line
}

// lineReader yields whole newline-delimited messages of unbounded size.
type lineReader struct{ r *bufio.Reader }

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, bufSize)}
}

// readLine returns the next message including its trailing newline (if any).
func (lr *lineReader) readLine() ([]byte, error) {
	return lr.r.ReadBytes('\n')
}

// dropNewline returns the line without a trailing \n or \r\n.
func dropNewline(line []byte) []byte {
	n := len(line)
	for n > 0 && (line[n-1] == '\n' || line[n-1] == '\r') {
		n--
	}
	return line[:n]
}
