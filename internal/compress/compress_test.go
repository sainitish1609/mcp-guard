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
