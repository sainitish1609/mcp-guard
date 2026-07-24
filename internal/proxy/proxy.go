// Package proxy is the core of mcp-guard: it launches the real MCP server as a
// child process and pumps the newline-delimited JSON-RPC stream in both
// directions, applying guard policy on the way out (client → server) and
// redaction, compression, and annotation on the way back (server → client).
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/sainitish1609/mcp-guard/internal/anomaly"
	"github.com/sainitish1609/mcp-guard/internal/audit"
	"github.com/sainitish1609/mcp-guard/internal/compress"
	"github.com/sainitish1609/mcp-guard/internal/config"
	"github.com/sainitish1609/mcp-guard/internal/guard"
	"github.com/sainitish1609/mcp-guard/internal/inject"
	"github.com/sainitish1609/mcp-guard/internal/jsonrpc"
	"github.com/sainitish1609/mcp-guard/internal/redact"
	"github.com/sainitish1609/mcp-guard/internal/stats"
)

// bufSize is the initial read buffer; ReadBytes grows without limit so large
// results (file contents, DB schemas) are never truncated.
const bufSize = 64 * 1024

// engines is the reloadable policy core. It is swapped atomically on SIGHUP so a
// running proxy can pick up config-file edits without dropping the connection.
type engines struct {
	cfg      config.Config
	guard    *guard.Guard
	redactor *redact.Engine
	injector *inject.Scanner
}

// Proxy holds the wired-up transformation pipeline and shared cross-goroutine
// state (the client stdout writer and the request→tool correlation map).
type Proxy struct {
	log      *audit.Logger
	eng      atomic.Pointer[engines] // reloadable policy engines
	detector *anomaly.Detector       // persists across reloads (keeps its window)
	stats    *stats.Stats            // persists across reloads (accumulates)
	reload   func() (config.Config, error)

	clientMu sync.Mutex // serializes all writes to the client (stdout)
	client   io.Writer

	pendingMu sync.Mutex
	pending   map[string]string // request id -> tool name, for result correlation
}

// buildEngines compiles the policy engines for a resolved config.
func buildEngines(cfg config.Config) *engines {
	red := redact.New(cfg.CustomPatterns)
	red.EnableEntropy(cfg.EntropyScan)
	red.SetEntropyMask(cfg.EntropyMask)
	return &engines{
		cfg:      cfg,
		guard:    guard.New(cfg),
		redactor: red,
		injector: inject.New(cfg.NeutralizeInjection),
	}
}

// newPipeline builds the transport-agnostic transformation core (guard,
// redactor, injector, detector, stats) from cfg. Both the stdio proxy and the
// HTTP proxy share this so policy behaves identically across transports.
func newPipeline(cfg config.Config, log *audit.Logger) *Proxy {
	p := &Proxy{
		log:      log,
		detector: anomaly.New(cfg.RateLimit),
		stats:    stats.New(),
		pending:  make(map[string]string),
	}
	p.eng.Store(buildEngines(cfg))
	return p
}

// e returns the current policy engines.
func (p *Proxy) e() *engines { return p.eng.Load() }

// Stats exposes the session counters for summary reporting.
func (p *Proxy) Stats() *stats.Stats { return p.stats }

// doReload re-resolves config (via the reload closure, if set) and swaps in
// freshly built engines. The detector and stats are intentionally preserved.
func (p *Proxy) doReload() {
	if p.reload == nil {
		return
	}
	cfg, err := p.reload()
	if err != nil {
		p.log.Debugf("config reload failed: %v", err)
		return
	}
	p.eng.Store(buildEngines(cfg))
	p.log.Notice("config reloaded")
}

// Run launches childCmd and proxies stdin/stdout through the guard pipeline until
// the child exits or ctx is cancelled. It returns the child's exit code. reload,
// if non-nil, re-resolves config on SIGHUP for hot policy reloads.
func Run(ctx context.Context, cfg config.Config, log *audit.Logger, childCmd []string, reload func() (config.Config, error)) (int, error) {
	if len(childCmd) == 0 {
		return 1, errors.New("no child command provided")
	}

	p := newPipeline(cfg, log)
	p.client = os.Stdout
	p.reload = reload

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Session summary on exit; live signal handling (SIGUSR1 snapshot, SIGHUP reload).
	if cfg.Stats {
		defer p.printSummary()
	}
	defer p.installSignals(ctx, cfg.Stats)()

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

// transformRequest inspects a client→server line for the stdio pump. It returns
// the bytes to forward to the child, or nil if the request was blocked (in which
// case an isError response has already been written back to the client).
func (p *Proxy) transformRequest(line []byte) []byte {
	forward, block := p.evaluateRequest(line)
	if block != nil {
		_ = p.writeClient(block)
	}
	return forward
}

// evaluateRequest is the transport-agnostic request pipeline. It returns the
// bytes to forward upstream (nil if blocked) and, when blocked, the isError
// response bytes to send back to the client (nil otherwise).
func (p *Proxy) evaluateRequest(line []byte) (forward, block []byte) {
	msg, err := jsonrpc.Parse(dropNewline(line))
	if err != nil || !msg.IsToolCall() {
		return line, nil // pass through untouched
	}

	e := p.e()
	tool := msg.ToolName()
	p.rememberTool(msg.ID, tool)
	args := msg.ToolArgs()

	// Detect (but do not mutate) secret-shaped data in outbound tool arguments,
	// so a secret the agent read cannot silently be forwarded to a phone-home
	// server without a trace. Mutation is intentionally avoided: some tools
	// legitimately need credentials in their arguments.
	if e.cfg.ScanRequests {
		if hits := p.scanArgSecrets(e, args); len(hits) > 0 {
			p.log.RequestSecret(tool, redact.Summary(hits))
			p.stats.RequestSecrets.Add(int64(totalHits(hits)))
		}
	}

	// Behavioral anomaly / rate limiting.
	if warn, rl := p.detector.Observe(e.guard.IsRead(tool)); warn != "" || rl {
		if warn != "" {
			p.log.Anomaly(tool, warn)
			p.stats.AnomalyWarnings.Add(1)
		}
		if rl {
			p.stats.RateBlocked.Add(1)
			if !e.cfg.DryRun {
				p.takeTool(msg.ID)
				return nil, p.blockBytes(msg.ID, "Blocked by mcp-guard: rate limit exceeded (throttled to protect against runaway/exfiltration)")
			}
		}
	}

	blocked, reason := e.guard.Inspect(tool, args)
	if !blocked {
		return line, nil
	}

	p.log.Blocked(tool, reason)
	p.accountBlock(reason)
	if e.cfg.DryRun {
		return line, nil // dry-run: log only, still forward
	}

	// Blocked: the child never sees this call and never produces a result for
	// this id, so drop the pending correlation we just recorded.
	p.takeTool(msg.ID)
	return nil, p.blockBytes(msg.ID, "Blocked by mcp-guard: "+reason)
}

// blockBytes builds a newline-terminated isError response for a blocked request.
func (p *Proxy) blockBytes(id json.RawMessage, text string) []byte {
	resp := jsonrpc.NewToolErrorResult(id, text)
	encoded, err := resp.Encode()
	if err != nil {
		return nil
	}
	return append(encoded, '\n')
}

// accountBlock increments the right stat counter based on the block reason.
func (p *Proxy) accountBlock(reason string) {
	switch {
	case strings.Contains(reason, "shell"):
		p.stats.ShellBlocked.Add(1)
	case strings.HasPrefix(reason, "read of"):
		p.stats.ReadsBlocked.Add(1)
	default:
		p.stats.WritesBlocked.Add(1)
	}
}

// scanArgSecrets runs the redactor over every string argument and returns the
// hits without altering the arguments. Audit-only entropy findings are excluded
// so a request warning means a genuine named-pattern match, not a base64 blob.
func (p *Proxy) scanArgSecrets(e *engines, args map[string]json.RawMessage) []redact.Hit {
	var all []redact.Hit
	for _, s := range argStrings(args) {
		if _, hits := e.redactor.Scan(s); len(hits) > 0 {
			for _, h := range hits {
				if !h.Audit {
					all = append(all, h)
				}
			}
		}
	}
	return all
}

// splitHits partitions hits into those that were masked and those that were only
// audited (entropy in its default audit-only mode).
func splitHits(hits []redact.Hit) (masked, audited []redact.Hit) {
	for _, h := range hits {
		if h.Audit {
			audited = append(audited, h)
		} else {
			masked = append(masked, h)
		}
	}
	return masked, audited
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

	e := p.e()
	tool := p.takeTool(msg.ID)
	changed := false

	// tools/list annotation.
	if e.cfg.AnnotateTools {
		if msg.MapToolListDescriptions(e.guard.Annotate) {
			changed = true
		}
	}

	// Redaction + injection defense scan every string in the result (not just
	// content[].text) so a secret is masked, and hidden-Unicode/injection
	// directives are neutralized, even in structuredContent or tool descriptions.
	if e.cfg.RedactSecrets || e.cfg.ScanInjection {
		var hits []redact.Hit
		var findings []inject.Finding
		if msg.MapResultStrings(func(t string) string {
			out := t
			if e.cfg.RedactSecrets {
				var h []redact.Hit
				out, h = e.redactor.Scan(out)
				hits = append(hits, h...)
			}
			if e.cfg.ScanInjection {
				var f []inject.Finding
				out, f = e.injector.Scan(out)
				findings = append(findings, f...)
			}
			return out
		}) {
			changed = true
		}
		if len(hits) > 0 {
			masked, audited := splitHits(hits)
			if len(masked) > 0 {
				p.log.Redacted(tool, redact.Summary(masked))
				for _, h := range masked {
					p.stats.AddRedaction(h.Pattern, h.Count)
				}
			}
			if len(audited) > 0 {
				p.log.EntropyAudit(tool, redact.AuditSummary(audited))
				for _, h := range audited {
					p.stats.EntropyAudited.Add(int64(h.Count))
				}
			}
		}
		if len(findings) > 0 {
			p.log.Injection(tool, inject.Summary(findings))
			for _, f := range findings {
				p.stats.InjectionsFound.Add(int64(f.Count))
			}
		}
	}

	// Compression (opt-in). Skip results from tools the agent edits round-trip.
	if e.cfg.Compress && !compress.SkipTool(tool) {
		var totBefore, totAfter, tokBefore, tokAfter int
		var truncatedAny bool
		if msg.MapResultText(func(t string) string {
			out, r := compress.Text(t, e.cfg.MaxTokens)
			totBefore += r.BytesBefore
			totAfter += r.BytesAfter
			tokBefore += compress.EstimateTokens(t)
			tokAfter += compress.EstimateTokens(out)
			truncatedAny = truncatedAny || r.Truncated
			return out
		}) {
			changed = true
			p.log.Compressed(tool, totBefore, totAfter, truncatedAny)
			p.stats.AddSaved(tokBefore-tokAfter, totBefore-totAfter)
		}
	}

	if !changed || e.cfg.DryRun {
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

// installSignals wires the interim stats snapshot (when stats is on) and the hot
// config reload signal until ctx is done. It returns a stop function. On
// platforms without these signals (Windows) it is a no-op.
func (p *Proxy) installSignals(ctx context.Context, stats bool) func() {
	watch := make([]os.Signal, 0, 2)
	if statsSignal != nil {
		watch = append(watch, statsSignal)
	}
	if reloadSignal != nil {
		watch = append(watch, reloadSignal)
	}
	if len(watch) == 0 {
		return func() {}
	}

	ch := make(chan os.Signal, len(watch))
	signal.Notify(ch, watch...)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-ch:
				switch {
				case statsSignal != nil && s == statsSignal:
					if stats {
						p.printSummary()
					}
				case reloadSignal != nil && s == reloadSignal:
					p.doReload()
				}
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// printSummary writes the session stats report to the audit log, unless nothing
// noteworthy happened.
func (p *Proxy) printSummary() {
	if p.stats == nil || p.stats.Empty() {
		return
	}
	p.log.Notice("\n" + p.stats.Summary(p.e().cfg.PricePer1kTokens))
}

// totalHits sums the counts across redaction hits.
func totalHits(hits []redact.Hit) int {
	n := 0
	for _, h := range hits {
		n += h.Count
	}
	return n
}

// argStrings extracts every string value (recursively) from tool-call arguments.
func argStrings(args map[string]json.RawMessage) []string {
	var out []string
	for _, raw := range args {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		collectArgStrings(v, &out)
	}
	return out
}

func collectArgStrings(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case []any:
		for _, e := range t {
			collectArgStrings(e, out)
		}
	case map[string]any:
		for _, e := range t {
			collectArgStrings(e, out)
		}
	}
}

// dropNewline returns the line without a trailing \n or \r\n.
func dropNewline(line []byte) []byte {
	n := len(line)
	for n > 0 && (line[n-1] == '\n' || line[n-1] == '\r') {
		n--
	}
	return line[:n]
}
