// Package compress performs conservative, opt-in token reduction on MCP result
// text: it strips code comments, collapses blank-line runs, trims trailing
// whitespace, and can cap output at an approximate token budget.
//
// Compression is deliberately cautious. Altering text a coding agent will later
// edit can corrupt its diff, so callers skip results from read-for-edit tools
// (see SkipTool) and the package never touches string-literal contents.
package compress

import "strings"

// readForEditTools are tool-name substrings whose results the agent typically
// edits round-trip; compressing them risks corrupting the agent's diff.
var readForEditTools = []string{"read_file", "get_file", "read_text", "open_file", "cat_file", "view_file", "get_contents"}

// SkipTool reports whether a tool's results must not be compressed.
func SkipTool(toolName string) bool {
	l := strings.ToLower(toolName)
	for _, t := range readForEditTools {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// approxTokens estimates token count as ~4 characters per token.
func approxTokens(s string) int { return (len(s) + 3) / 4 }

// Result reports what a Text call did, for auditing.
type Result struct {
	Changed        bool
	BytesBefore    int
	BytesAfter     int
	Truncated      bool
}

// Text compresses a single text block. maxTokens <= 0 disables truncation.
func Text(text string, maxTokens int) (string, Result) {
	before := len(text)
	out := stripComments(text)
	out = collapseWhitespace(out)

	res := Result{BytesBefore: before}
	truncated := false
	if maxTokens > 0 && approxTokens(out) > maxTokens {
		out = truncate(out, maxTokens)
		truncated = true
	}
	res.BytesAfter = len(out)
	res.Truncated = truncated
	res.Changed = out != text
	return out, res
}

// stripComments removes // line comments and /* */ block comments while leaving
// the contents of "..." and '...' and `...` string literals untouched. This is
// a language-agnostic lexer covering C-family, Go, JS/TS, Java, and similar.
func stripComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	const (
		normal = iota
		lineComment
		blockComment
		dquote
		squote
		btick
	)
	state := normal
	for i := 0; i < len(s); i++ {
		c := s[i]
		var next byte
		if i+1 < len(s) {
			next = s[i+1]
		}
		switch state {
		case normal:
			switch {
			case c == '/' && next == '/':
				state = lineComment
				i++
			case c == '/' && next == '*':
				state = blockComment
				i++
			case c == '"':
				state = dquote
				b.WriteByte(c)
			case c == '\'':
				state = squote
				b.WriteByte(c)
			case c == '`':
				state = btick
				b.WriteByte(c)
			default:
				b.WriteByte(c)
			}
		case lineComment:
			if c == '\n' {
				state = normal
				b.WriteByte(c)
			}
		case blockComment:
			if c == '*' && next == '/' {
				state = normal
				i++
			}
		case dquote:
			b.WriteByte(c)
			if c == '\\' {
				if i+1 < len(s) {
					b.WriteByte(next)
					i++
				}
			} else if c == '"' {
				state = normal
			}
		case squote:
			b.WriteByte(c)
			if c == '\\' {
				if i+1 < len(s) {
					b.WriteByte(next)
					i++
				}
			} else if c == '\'' {
				state = normal
			}
		case btick:
			b.WriteByte(c)
			if c == '`' {
				state = normal
			}
		}
	}
	return b.String()
}

// collapseWhitespace trims trailing whitespace per line and collapses runs of
// three or more blank lines into a single blank line.
func collapseWhitespace(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	blankRun := 0
	for _, ln := range lines {
		trimmed := strings.TrimRight(ln, " \t\r")
		if strings.TrimSpace(trimmed) == "" {
			blankRun++
			if blankRun > 1 {
				continue
			}
			out = append(out, "")
			continue
		}
		blankRun = 0
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}

// truncate cuts s to roughly maxTokens tokens and appends a visible marker.
func truncate(s string, maxTokens int) string {
	limit := maxTokens * 4
	if limit >= len(s) {
		return s
	}
	// Prefer cutting at a line boundary near the limit.
	cut := limit
	if idx := strings.LastIndexByte(s[:limit], '\n'); idx > limit/2 {
		cut = idx
	}
	return s[:cut] + "\n…[truncated by mcp-guard]…"
}
