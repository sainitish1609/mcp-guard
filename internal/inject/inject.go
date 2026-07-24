// Package inject defends against prompt-injection and tool-poisoning: content
// returned by an MCP server (file bodies, web pages, even a malicious server's
// own tool descriptions) can carry instructions aimed at the agent rather than
// the user. Two vectors are handled:
//
//   - Hidden Unicode: "tag" characters (U+E0000–U+E007F) that encode invisible
//     ASCII, bidirectional-override controls that reorder displayed text, and
//     zero-width spaces used to smuggle or fragment payloads.
//   - Textual directives: high-signal override phrases such as "ignore all
//     previous instructions" or "do not tell the user".
//
// Hidden Unicode is always stripped (invisible, near-zero false-positive risk).
// Detected directives are neutralized in place with a visible marker so the
// instruction cannot act, while the surrounding readable content is preserved.
package inject

import (
	"fmt"
	"sort"
	"strings"
)

// neutralizedMarker replaces a detected injection directive. It is intentionally
// visible so a human reviewing the transcript sees what mcp-guard defanged.
const neutralizedMarker = "[mcp-guard: neutralized-injection]"

// Finding records one class of detection for auditing.
type Finding struct {
	Kind   string // "hidden-unicode" or "injection-directive"
	Detail string // short descriptor, e.g. "tag-chars" or the matched phrase kind
	Count  int
}

// Scanner strips hidden Unicode and neutralizes injection directives.
type Scanner struct {
	neutralize bool // when false, directives are only detected (reported), not rewritten
}

// New builds a Scanner. If neutralize is false, textual directives are still
// reported but left in place (hidden Unicode is always stripped).
func New(neutralize bool) *Scanner {
	return &Scanner{neutralize: neutralize}
}

// Scan sanitizes text, returning the cleaned string and any findings. When
// nothing is detected the input is returned unchanged with nil findings.
func (s *Scanner) Scan(text string) (string, []Finding) {
	if text == "" {
		return text, nil
	}
	counts := map[string]int{}

	out, hidden := stripHidden(text)
	for k, v := range hidden {
		counts[k] += v
	}

	out = directiveRE.ReplaceAllStringFunc(out, func(m string) string {
		counts["injection-directive"]++
		if s.neutralize {
			return neutralizedMarker
		}
		return m
	})

	if len(counts) == 0 {
		return text, nil
	}
	return out, toFindings(counts)
}

// toFindings converts the count map into a stable, sorted slice.
func toFindings(counts map[string]int) []Finding {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Finding, 0, len(keys))
	for _, k := range keys {
		kind := "hidden-unicode"
		if k == "injection-directive" {
			kind = "injection-directive"
		}
		out = append(out, Finding{Kind: kind, Detail: k, Count: counts[k]})
	}
	return out
}

// stripHidden removes hidden/deceptive runes, tallying them by category. Runes
// legitimately used in human scripts and emoji (ZWNJ U+200C, ZWJ U+200D) are
// deliberately preserved to avoid corrupting real text.
func stripHidden(s string) (string, map[string]int) {
	counts := map[string]int{}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch cat := hiddenCategory(r); cat {
		case "":
			b.WriteRune(r)
		default:
			counts[cat]++
		}
	}
	return b.String(), counts
}

// hiddenCategory returns a non-empty category name for runes that should be
// stripped, or "" for runes to keep.
func hiddenCategory(r rune) string {
	switch {
	case r >= 0xE0000 && r <= 0xE007F:
		return "tag-chars" // Unicode Tags: invisible ASCII smuggling
	case r >= 0x202A && r <= 0x202E:
		return "bidi-override" // LRE/RLE/PDF/LRO/RLO
	case r >= 0x2066 && r <= 0x2069:
		return "bidi-isolate" // LRI/RLI/FSI/PDI
	case r == 0x200B || r == 0x2060 || r == 0xFEFF:
		return "zero-width" // ZWSP, word-joiner, BOM/ZWNBSP
	case r >= 0x2061 && r <= 0x2064:
		return "invisible-op" // invisible mathematical operators
	case r == 0x00AD:
		return "soft-hyphen"
	default:
		return ""
	}
}

// Summary renders findings compactly for the audit log.
func Summary(fs []Finding) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("%s:%d", f.Detail, f.Count))
	}
	return strings.Join(parts, " ")
}
