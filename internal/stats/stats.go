// Package stats accumulates what mcp-guard did over a session — secrets masked,
// writes blocked, injections neutralized, and tokens saved — so the otherwise
// invisible protection can be reported as concrete numbers on exit.
//
// All counters are updated with atomic operations so both proxy pumps (and the
// HTTP handler goroutines) can record concurrently without locking.
package stats

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Stats holds session counters.
type Stats struct {
	SecretsRedacted atomic.Int64
	WritesBlocked   atomic.Int64
	ReadsBlocked    atomic.Int64
	ShellBlocked    atomic.Int64
	RateBlocked     atomic.Int64
	InjectionsFound atomic.Int64
	RequestSecrets  atomic.Int64
	AnomalyWarnings atomic.Int64
	EntropyAudited  atomic.Int64
	TokensSaved     atomic.Int64
	BytesSaved      atomic.Int64

	mu     sync.Mutex
	byType map[string]int64 // redactions broken down by pattern label
}

// New returns an initialized Stats.
func New() *Stats { return &Stats{byType: map[string]int64{}} }

// AddRedaction records n masks of the given pattern label.
func (s *Stats) AddRedaction(label string, n int) {
	if n <= 0 {
		return
	}
	s.SecretsRedacted.Add(int64(n))
	s.mu.Lock()
	s.byType[label] += int64(n)
	s.mu.Unlock()
}

// AddSaved records tokens and bytes removed by compression.
func (s *Stats) AddSaved(tokens, bytes int) {
	if tokens > 0 {
		s.TokensSaved.Add(int64(tokens))
	}
	if bytes > 0 {
		s.BytesSaved.Add(int64(bytes))
	}
}

// Empty reports whether nothing noteworthy happened (used to suppress a noisy
// zero summary).
func (s *Stats) Empty() bool {
	return s.SecretsRedacted.Load() == 0 && s.WritesBlocked.Load() == 0 &&
		s.ReadsBlocked.Load() == 0 && s.ShellBlocked.Load() == 0 &&
		s.RateBlocked.Load() == 0 && s.InjectionsFound.Load() == 0 &&
		s.RequestSecrets.Load() == 0 && s.TokensSaved.Load() == 0 &&
		s.AnomalyWarnings.Load() == 0 && s.EntropyAudited.Load() == 0
}

// Summary renders a multi-line human report. pricePer1k (USD per 1000 tokens)
// drives the estimated cost saving; pass 0 to omit the dollar line.
func (s *Stats) Summary(pricePer1k float64) string {
	var b strings.Builder
	b.WriteString("mcp-guard session summary\n")
	line := func(label string, v int64) {
		if v > 0 {
			fmt.Fprintf(&b, "  %-22s %d\n", label, v)
		}
	}
	line("secrets redacted", s.SecretsRedacted.Load())

	// Per-type breakdown, sorted for stable output.
	s.mu.Lock()
	types := make([]string, 0, len(s.byType))
	for k := range s.byType {
		types = append(types, k)
	}
	sort.Strings(types)
	for _, k := range types {
		fmt.Fprintf(&b, "      %-18s %d\n", k, s.byType[k])
	}
	s.mu.Unlock()

	line("writes blocked", s.WritesBlocked.Load())
	line("reads blocked", s.ReadsBlocked.Load())
	line("shell blocked", s.ShellBlocked.Load())
	line("rate-limit blocks", s.RateBlocked.Load())
	line("injections neutralized", s.InjectionsFound.Load())
	line("secrets in requests", s.RequestSecrets.Load())
	line("entropy flagged (audit)", s.EntropyAudited.Load())
	line("anomaly warnings", s.AnomalyWarnings.Load())
	line("tokens saved", s.TokensSaved.Load())
	line("bytes saved", s.BytesSaved.Load())

	if pricePer1k > 0 {
		saved := float64(s.TokensSaved.Load()) / 1000.0 * pricePer1k
		if saved > 0 {
			fmt.Fprintf(&b, "  %-22s $%.4f\n", "est. cost saved", saved)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
