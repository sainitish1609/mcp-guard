// Package audit emits mcp-guard's activity log. All output goes to stderr —
// stdout is reserved exclusively for the MCP protocol stream.
package audit

import (
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
}

// New builds a Logger at the given level. dryRun is recorded so entries can be
// marked as would-be actions.
func New(level config.LogLevel, dryRun bool) *Logger {
	if level == "" {
		level = config.LogInfo
	}
	return &Logger{w: os.Stderr, level: level, dryRun: dryRun}
}

func (l *Logger) enabled(at config.LogLevel) bool {
	return levelRank[l.level] >= levelRank[at]
}

func (l *Logger) write(at config.LogLevel, action, detail string) {
	if !l.enabled(at) {
		return
	}
	prefix := "mcp-guard"
	if l.dryRun {
		prefix = "mcp-guard[dry-run]"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s %-10s %s\n", time.Now().Format(time.RFC3339), prefix, action, detail)
}

// Blocked logs a policy block (error level — always shown unless silent).
func (l *Logger) Blocked(tool, reason string) {
	l.write(config.LogError, "blocked", fmt.Sprintf("tool=%q %s", tool, reason))
}

// Redacted logs secret masking in a result.
func (l *Logger) Redacted(tool, summary string) {
	l.write(config.LogInfo, "redacted", fmt.Sprintf("tool=%q %s", tool, summary))
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
