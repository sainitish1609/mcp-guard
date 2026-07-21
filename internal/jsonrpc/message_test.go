package jsonrpc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToolCallParsing(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/x"}}}`)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsToolCall() {
		t.Fatal("expected tools/call")
	}
	if m.ToolName() != "write_file" {
		t.Fatalf("tool name = %q", m.ToolName())
	}
	if _, ok := m.ToolArgs()["path"]; !ok {
		t.Fatal("expected path argument")
	}
}

func TestNewToolErrorResultShape(t *testing.T) {
	id := json.RawMessage("42")
	m := NewToolErrorResult(id, "blocked: nope")
	if m.Error != nil {
		t.Fatal("policy block must NOT be a JSON-RPC error object")
	}
	if string(m.ID) != "42" {
		t.Fatalf("id not preserved: %s", m.ID)
	}
	var res struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected isError:true")
	}
	if len(res.Content) != 1 || res.Content[0].Text != "blocked: nope" {
		t.Fatalf("unexpected content: %+v", res.Content)
	}
}

func TestMapResultTextRedactsAndPreservesOtherFields(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[{"type":"text","text":"secret"},{"type":"image","data":"zzz"}],"meta":{"k":"v"}}}`)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	changed := m.MapResultText(func(s string) string {
		if s == "secret" {
			return "MASKED"
		}
		return s
	})
	if !changed {
		t.Fatal("expected change")
	}
	out := string(m.Result)
	if !strings.Contains(out, "MASKED") {
		t.Fatalf("text not rewritten: %s", out)
	}
	if !strings.Contains(out, `"type":"image"`) || !strings.Contains(out, `"data":"zzz"`) {
		t.Fatalf("non-text block lost: %s", out)
	}
	if !strings.Contains(out, `"meta"`) {
		t.Fatalf("unrelated result field lost: %s", out)
	}
}

func TestMapResultStringsReachesNestedFields(t *testing.T) {
	// Mirrors the real filesystem server: the same text appears in content[].text
	// AND in structuredContent.content. Both must be redacted.
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"k AKIAIOSFODNN7EXAMPLE"}],"structuredContent":{"content":"k AKIAIOSFODNN7EXAMPLE"},"count":42}}`)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	changed := m.MapResultStrings(func(s string) string {
		return strings.ReplaceAll(s, "AKIAIOSFODNN7EXAMPLE", "[MASK]")
	})
	if !changed {
		t.Fatal("expected change")
	}
	out := string(m.Result)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret leaked in some field: %s", out)
	}
	if strings.Count(out, "[MASK]") != 2 {
		t.Fatalf("expected both content and structuredContent masked: %s", out)
	}
	if !strings.Contains(out, `"count":42`) {
		t.Fatalf("numeric field not preserved exactly: %s", out)
	}
}

func TestMapToolListDescriptions(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","description":"does a"},{"name":"b"}]}}`)
	m, _ := Parse(raw)
	changed := m.MapToolListDescriptions(func(d string) string { return d + " [note]" })
	if !changed {
		t.Fatal("expected change")
	}
	out := string(m.Result)
	if !strings.Contains(out, "does a [note]") {
		t.Fatalf("description a not annotated: %s", out)
	}
	if !strings.Contains(out, `" [note]"`) && !strings.Contains(out, `[note]`) {
		t.Fatalf("description b (empty) not annotated: %s", out)
	}
}

func TestPassthroughNonJSON(t *testing.T) {
	_, err := Parse([]byte("this is not json"))
	if err == nil {
		t.Fatal("expected parse error for non-JSON")
	}
}
