// Package audit emits mcp-guard's activity log. All output goes to stderr —
// stdout is reserved exclusively for the MCP protocol stream. Records can be
// rendered as aligned human-readable text (default) or as JSON Lines for
// ingestion by a SIEM or log pipeline (--log-format json).
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sainitish1609/mcp-guard/internal/config"
)

// levelRank orders log levels for threshold comparison.
var levelRank = map[config.LogLevel]int{
	config.LogSilent: 0,
	config.LogError:  1,
	config.LogInfo:   2,
	config.LogDebug:  3,
}

// Logger writes structured, single-line audit records to stderr.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	level  config.LogLevel
	dryRun bool
	json   bool
}

// New builds a Logger at the given level. dryRun is recorded so entries can be
// marked as would-be actions.
func New(level config.LogLevel, dryRun bool) *Logger {
	if level == "" {
		level = config.LogInfo
	}
	return &Logger{w: os.Stderr, level: level, dryRun: dryRun}
}

// SetJSON switches record rendering to JSON Lines.
func (l *Logger) SetJSON(on bool) { l.json = on }

func (l *Logger) enabled(at config.LogLevel) bool {
	return levelRank[l.level] >= levelRank[at]
}

func (l *Logger) write(at config.LogLevel, action, detail string) {
	if !l.enabled(at) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().Format(time.RFC3339)
	if l.json {
		rec := map[string]any{"ts": ts, "level": string(at), "event": action, "detail": detail}
		if l.dryRun {
			rec["dry_run"] = true
		}
		b, _ := json.Marshal(rec)
		fmt.Fprintf(l.w, "%s\n", b)
		return
	}
	prefix := "mcp-guard"
	if l.dryRun {
		prefix = "mcp-guard[dry-run]"
	}
	fmt.Fprintf(l.w, "%s %s %-10s %s\n", ts, prefix, action, detail)
}

// Blocked logs a policy block (error level — always shown unless silent).
func (l *Logger) Blocked(tool, reason string) {
	l.write(config.LogError, "blocked", fmt.Sprintf("tool=%q %s", tool, reason))
}

// Redacted logs secret masking in a result.
func (l *Logger) Redacted(tool, summary string) {
	l.write(config.LogInfo, "redacted", fmt.Sprintf("tool=%q %s", tool, summary))
}

// EntropyAudit logs high-entropy candidates that were flagged but NOT masked
// (audit-only mode). The payload is unchanged; this is a heads-up with offsets.
func (l *Logger) EntropyAudit(tool, summary string) {
	l.write(config.LogInfo, "entropy", fmt.Sprintf("tool=%q flagged (audit-only, not masked) %s", tool, summary))
}

// Injection logs neutralized/observed prompt-injection content in a result.
func (l *Logger) Injection(tool, summary string) {
	l.write(config.LogError, "injection", fmt.Sprintf("tool=%q %s", tool, summary))
}

// RequestSecret warns that a client→server tool call carried secret-shaped data.
func (l *Logger) RequestSecret(tool, summary string) {
	l.write(config.LogError, "req-secret", fmt.Sprintf("tool=%q %s", tool, summary))
}

// Anomaly logs a behavioral warning (rate/read-burst).
func (l *Logger) Anomaly(tool, detail string) {
	l.write(config.LogError, "anomaly", fmt.Sprintf("tool=%q %s", tool, detail))
}

// Compressed logs a token-reduction on a result.
func (l *Logger) Compressed(tool string, before, after int, truncated bool) {
	saved := before - after
	l.write(config.LogInfo, "compressed", fmt.Sprintf("tool=%q saved=%dB truncated=%v", tool, saved, truncated))
}

// Debugf logs a free-form debug entry.
func (l *Logger) Debugf(format string, args ...any) {
	l.write(config.LogDebug, "debug", fmt.Sprintf(format, args...))
}

// Startup logs the effective configuration once at launch.
func (l *Logger) Startup(detail string) {
	l.write(config.LogInfo, "startup", detail)
}

// Notice logs an info-level message verbatim (used for the session summary).
func (l *Logger) Notice(detail string) {
	l.write(config.LogInfo, "summary", detail)
}
