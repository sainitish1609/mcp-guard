package compress

import (
	"strings"
	"testing"
)

func TestStripLineAndBlockComments(t *testing.T) {
	in := "code(); // trailing\n/* block\nmore */\nkeep();"
	out := stripComments(in)
	if strings.Contains(out, "trailing") || strings.Contains(out, "block") {
		t.Fatalf("comments not stripped: %q", out)
	}
	if !strings.Contains(out, "code();") || !strings.Contains(out, "keep();") {
		t.Fatalf("code removed: %q", out)
	}
}

func TestPreservesStringLiterals(t *testing.T) {
	in := `s := "http://not-a-comment"; c := '/'; k := ` + "`" + `raw // not comment` + "`"
	out := stripComments(in)
	if !strings.Contains(out, "http://not-a-comment") {
		t.Fatalf("double-quote literal damaged: %q", out)
	}
	if !strings.Contains(out, "raw // not comment") {
		t.Fatalf("backtick literal damaged: %q", out)
	}
}

func TestCollapseBlankLines(t *testing.T) {
	in := "a\n\n\n\n\nb"
	out := collapseWhitespace(in)
	if strings.Count(out, "\n\n\n") != 0 {
		t.Fatalf("blank runs not collapsed: %q", out)
	}
	if !strings.Contains(out, "a\n\nb") {
		t.Fatalf("unexpected collapse result: %q", out)
	}
}

func TestTruncationMarker(t *testing.T) {
	in := strings.Repeat("x", 4000)
	out, res := Text(in, 100) // ~100 tokens => ~400 chars
	if !res.Truncated {
		t.Fatal("expected truncation")
	}
	if !strings.Contains(out, "truncated by mcp-guard") {
		t.Fatalf("missing truncation marker: %q", out[len(out)-40:])
	}
	if len(out) >= len(in) {
		t.Fatalf("output not shortened: %d >= %d", len(out), len(in))
	}
}

func TestSkipTool(t *testing.T) {
	if !SkipTool("read_file") {
		t.Fatal("read_file should be skipped")
	}
	if !SkipTool("get_file_contents") {
		t.Fatal("get_file_contents should be skipped")
	}
	if SkipTool("list_tables") {
		t.Fatal("list_tables should not be skipped")
	}
}

func TestEstimateTokens(t *testing.T) {
	// Word runs, punctuation, and symbols each contribute; empty is zero.
	if EstimateTokens("") != 0 {
		t.Fatal("empty should be 0 tokens")
	}
	if got := EstimateTokens("hello world"); got != 2 {
		t.Fatalf("two words = 2 tokens, got %d", got)
	}
	// Code with punctuation yields more tokens than a flat word count.
	if got := EstimateTokens("foo(bar, baz);"); got < 6 {
		t.Fatalf("expected punctuation-aware count, got %d", got)
	}
}
