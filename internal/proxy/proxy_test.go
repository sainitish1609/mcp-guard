package proxy

import (
	"strings"
	"testing"

	"github.com/sainitish1609/mcp-guard/internal/audit"
	"github.com/sainitish1609/mcp-guard/internal/config"
	"github.com/sainitish1609/mcp-guard/internal/guard"
	"github.com/sainitish1609/mcp-guard/internal/redact"
)

func newProxy(cfg config.Config) *Proxy {
	cfg.ExpandPaths()
	return &Proxy{
		cfg:      cfg,
		log:      audit.New(config.LogSilent, false),
		guard:    guard.New(cfg),
		redactor: redact.New(cfg.CustomPatterns),
		pending:  make(map[string]string),
	}
}

func TestTransformRequestBlocksProtectedWrite(t *testing.T) {
	p := newProxy(config.Default())
	line := []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.ssh/authorized_keys","content":"x"}}}` + "\n")

	var out strings.Builder
	p.client = &out

	fwd := p.transformRequest(line)
	if fwd != nil {
		t.Fatal("blocked request must not be forwarded to the child")
	}
	resp := out.String()
	if !strings.Contains(resp, `"isError":true`) {
		t.Fatalf("expected isError result to client, got %q", resp)
	}
	if strings.Contains(resp, `"error"`) {
		t.Fatalf("policy block must not use a JSON-RPC error object: %q", resp)
	}
	if !strings.Contains(resp, `"id":9`) {
		t.Fatalf("response must preserve request id: %q", resp)
	}
}

func TestTransformRequestAllowsBenign(t *testing.T) {
	p := newProxy(config.Default())
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"./main.go"}}}` + "\n")
	fwd := p.transformRequest(line)
	if fwd == nil {
		t.Fatal("benign request should be forwarded")
	}
}

func TestTransformRequestPassthroughNonToolCall(t *testing.T) {
	p := newProxy(config.Default())
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	fwd := p.transformRequest(line)
	if string(fwd) != string(line) {
		t.Fatalf("initialize should pass through byte-for-byte")
	}
}

func TestTransformResponseRedacts(t *testing.T) {
	p := newProxy(config.Default())
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"key AKIAIOSFODNN7EXAMPLE"}]}}` + "\n")
	out := p.transformResponse(line)
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret leaked through proxy: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED:aws-access-key]") {
		t.Fatalf("expected mask in output: %s", out)
	}
}

func TestTransformResponseAnnotatesToolList(t *testing.T) {
	p := newProxy(config.Default())
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read","description":"reads"}]}}` + "\n")
	out := p.transformResponse(line)
	if !strings.Contains(string(out), guard.AnnotationMarker) {
		t.Fatalf("expected tools/list annotation: %s", out)
	}
}

func TestTransformResponsePassthroughWhenClean(t *testing.T) {
	p := newProxy(config.Default())
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"nothing secret here"}]}}` + "\n")
	out := p.transformResponse(line)
	if string(out) != string(line) {
		t.Fatalf("clean response should pass through unchanged:\n in: %s\nout: %s", line, out)
	}
}

func TestLargeMessageNotTruncatedByFraming(t *testing.T) {
	// A result far larger than bufio.Scanner's default 64KB token cap must survive
	// intact — this is why the pump uses bufio.Reader.ReadBytes, not Scanner.
	big := strings.Repeat("x", 512*1024)
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + big + `"}]}}` + "\n")
	lr := newLineReader(strings.NewReader(string(line)))
	got, err := lr.readLine()
	if err != nil && len(got) != len(line) {
		t.Fatalf("read error before full line: %v", err)
	}
	if len(got) != len(line) {
		t.Fatalf("large line truncated: got %d bytes, want %d", len(got), len(line))
	}
}

func TestDropNewline(t *testing.T) {
	if string(dropNewline([]byte("abc\r\n"))) != "abc" {
		t.Fatal("crlf not stripped")
	}
	if string(dropNewline([]byte("abc"))) != "abc" {
		t.Fatal("no-newline case altered")
	}
}

func TestCompressSkipsReadForEdit(t *testing.T) {
	cfg := config.Default()
	cfg.Compress = true
	p := newProxy(cfg)
	// Correlate id 1 with a read_file tool so compression is skipped.
	p.rememberTool([]byte("1"), "read_file")
	text := "code(); // comment that would be stripped\n\n\n\nmore();"
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + jsonString(text) + `}]}}` + "\n")
	out := p.transformResponse(line)
	if !strings.Contains(string(out), "comment that would be stripped") {
		t.Fatalf("read_file result must not be compressed: %s", out)
	}
}

// jsonString returns s as a JSON string literal (with surrounding quotes).
func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
