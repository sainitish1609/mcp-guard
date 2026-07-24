// Package redact scans MCP tool/resource result text for credential-shaped
// content and masks it before it can reach the LLM. It operates purely on the
// text content blocks of a result and never alters protocol structure.
package redact

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sainitish1609/mcp-guard/internal/config"
)

// Hit records a single pattern's activity for auditing. Audit is true for
// findings that were detected but NOT masked (the entropy catch-all in its
// default audit-only mode); Spans carries the byte offsets of those findings in
// the scanned string so the log can point at exactly what tripped the detector.
type Hit struct {
	Pattern string
	Count   int
	Audit   bool
	Spans   [][2]int
}

// Engine holds the compiled pattern set (built-ins plus any custom patterns).
type Engine struct {
	patterns    []Pattern
	entropy     bool
	entropyMask bool
}

// New builds an Engine from the built-in patterns and any user custom patterns.
// Invalid custom regexes are skipped rather than failing the whole proxy.
func New(custom []config.CustomPattern) *Engine {
	pats := make([]Pattern, len(builtinPatterns))
	copy(pats, builtinPatterns)
	for _, c := range custom {
		re, err := regexp.Compile(c.Regex)
		if err != nil {
			continue
		}
		name := c.Name
		if name == "" {
			name = "custom"
		}
		pats = append(pats, Pattern{Name: name, re: re})
	}
	return &Engine{patterns: pats}
}

// EnableEntropy toggles the high-entropy catch-all pass, which flags generated
// credentials that match no named pattern.
func (e *Engine) EnableEntropy(on bool) { e.entropy = on }

// SetEntropyMask controls whether entropy findings are masked (true) or only
// reported for auditing (false). Audit-only is the default because the entropy
// heuristic legitimately fires on integrity hashes, base64 fixtures, and signed
// URLs — masking those would silently corrupt otherwise-valid data.
func (e *Engine) SetEntropyMask(on bool) { e.entropyMask = on }

// mask is the redaction placeholder for a given pattern name.
func mask(name string) string { return "[REDACTED:" + name + "]" }

// Scan masks every secret occurrence in text and returns the sanitized string
// plus a per-pattern hit tally. The input is returned unchanged (and hits nil)
// when nothing matches.
func (e *Engine) Scan(text string) (string, []Hit) {
	if text == "" {
		return text, nil
	}
	var hits []Hit
	out := text
	for _, p := range e.patterns {
		if p.maskGroup > 0 {
			if count := e.maskSubgroup(&out, p); count > 0 {
				hits = append(hits, Hit{Pattern: p.Name, Count: count})
			}
			continue
		}
		matches := p.re.FindAllString(out, -1)
		if len(matches) == 0 {
			continue
		}
		out = p.re.ReplaceAllString(out, mask(p.Name))
		hits = append(hits, Hit{Pattern: p.Name, Count: len(matches)})
	}
	if e.entropy {
		if masked, spans := scanEntropy(out, e.entropyMask); len(spans) > 0 {
			out = masked // unchanged in audit-only mode
			hits = append(hits, Hit{
				Pattern: "high-entropy",
				Count:   len(spans),
				Audit:   !e.entropyMask,
				Spans:   spans,
			})
		}
	}
	return out, hits
}

// maskSubgroup replaces only the maskGroup submatch of every match, preserving
// the rest of the matched text. It skips values already masked by an earlier,
// more specific pattern so precise labels are not clobbered. Returns the number
// of replacements made and updates *out in place.
func (e *Engine) maskSubgroup(out *string, p Pattern) int {
	s := *out
	var b strings.Builder
	count := 0
	last := 0
	for _, loc := range p.re.FindAllStringSubmatchIndex(s, -1) {
		vs, ve := loc[2*p.maskGroup], loc[2*p.maskGroup+1]
		if vs < 0 {
			continue // group did not participate in this match
		}
		if strings.HasPrefix(s[vs:ve], "[REDACTED") {
			continue // already masked by a more specific pattern
		}
		b.WriteString(s[last:vs])
		b.WriteString(mask(p.Name))
		last = ve
		count++
	}
	if count == 0 {
		return 0
	}
	b.WriteString(s[last:])
	*out = b.String()
	return count
}

// Summary renders hits as a compact, log-friendly string like "aws-access-key:1 jwt:2".
func Summary(hits []Hit) string {
	s := ""
	for i, h := range hits {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("%s:%d", h.Pattern, h.Count)
	}
	return s
}

// AuditSummary renders audit-only hits with their byte offsets, e.g.
// "high-entropy:2 offsets=[12-44,80-120]", so an operator can locate exactly
// what the detector flagged without masking anything.
func AuditSummary(hits []Hit) string {
	s := ""
	for i, h := range hits {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("%s:%d", h.Pattern, h.Count)
		if len(h.Spans) > 0 {
			s += " offsets=["
			for j, sp := range h.Spans {
				if j > 0 {
					s += ","
				}
				s += fmt.Sprintf("%d-%d", sp[0], sp[1])
			}
			s += "]"
		}
	}
	return s
}
