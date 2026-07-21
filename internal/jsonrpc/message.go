// Package jsonrpc provides minimal helpers for inspecting and rewriting the
// JSON-RPC 2.0 messages that flow across the MCP stdio transport.
//
// Fields that mcp-guard does not need to touch (id, params, result) are kept as
// json.RawMessage so they can be re-emitted byte-for-byte, avoiding any lossy
// re-encoding of the underlying MCP payload.
package jsonrpc

import (
	"bytes"
	"encoding/json"
)

// Message is a decoded JSON-RPC 2.0 request, response, or notification. Only the
// fields mcp-guard reasons about are typed; the rest ride along untouched.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is the JSON-RPC error object. Reserved for genuine internal proxy
// failures — policy blocks use an isError result instead (see NewToolErrorResult).
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Parse decodes a single newline-delimited JSON-RPC message. A non-nil error
// means the bytes are not valid JSON-RPC and should be forwarded untouched.
func Parse(raw []byte) (*Message, error) {
	var m Message
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// IsRequest reports whether the message is a request or notification carrying a
// method (as opposed to a response carrying result/error).
func (m *Message) IsRequest() bool { return m.Method != "" }

// IsToolCall reports whether this is a tools/call request.
func (m *Message) IsToolCall() bool { return m.Method == "tools/call" }

// toolCallParams mirrors the params of a tools/call request.
type toolCallParams struct {
	Name      string                     `json:"name"`
	Arguments map[string]json.RawMessage `json:"arguments"`
}

// ToolName returns the tool name of a tools/call request, or "" if absent.
func (m *Message) ToolName() string {
	if !m.IsToolCall() || len(m.Params) == 0 {
		return ""
	}
	var p toolCallParams
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return ""
	}
	return p.Name
}

// ToolArgs returns the decoded arguments of a tools/call request.
func (m *Message) ToolArgs() map[string]json.RawMessage {
	if !m.IsToolCall() || len(m.Params) == 0 {
		return nil
	}
	var p toolCallParams
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return nil
	}
	return p.Arguments
}

// MapResultText applies fn to every text content block of the result and, if any
// text changed, rewrites m.Result. It preserves non-text blocks and unrelated
// result fields untouched.
func (m *Message) MapResultText(fn func(string) string) (changed bool) {
	if len(m.Result) == 0 {
		return false
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(m.Result, &generic); err != nil {
		return false
	}
	rawContent, ok := generic["content"]
	if !ok {
		return false
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(rawContent, &blocks); err != nil {
		return false
	}
	for i, b := range blocks {
		typeRaw, ok := b["type"]
		if !ok {
			continue
		}
		var t string
		if err := json.Unmarshal(typeRaw, &t); err != nil || t != "text" {
			continue
		}
		textRaw, ok := b["text"]
		if !ok {
			continue
		}
		var text string
		if err := json.Unmarshal(textRaw, &text); err != nil {
			continue
		}
		out := fn(text)
		if out != text {
			encoded, err := json.Marshal(out)
			if err != nil {
				continue
			}
			blocks[i]["text"] = encoded
			changed = true
		}
	}
	if !changed {
		return false
	}
	newContent, err := json.Marshal(blocks)
	if err != nil {
		return false
	}
	generic["content"] = newContent
	newResult, err := json.Marshal(generic)
	if err != nil {
		return false
	}
	m.Result = newResult
	return true
}

// MapResultStrings applies fn to every string value anywhere in the result,
// recursing through nested objects and arrays. This is used for redaction so a
// secret is masked no matter which field a server places it in (e.g. both the
// standard content[].text block and a structuredContent mirror). Numbers are
// preserved exactly via json.Number to avoid precision loss on re-encoding.
func (m *Message) MapResultStrings(fn func(string) string) (changed bool) {
	if len(m.Result) == 0 {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(m.Result))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	nv, ch := walkStrings(v, fn)
	if !ch {
		return false
	}
	out, err := json.Marshal(nv)
	if err != nil {
		return false
	}
	m.Result = out
	return true
}

// walkStrings recursively applies fn to string leaves, reporting whether any
// value changed.
func walkStrings(v any, fn func(string) string) (any, bool) {
	switch t := v.(type) {
	case string:
		out := fn(t)
		return out, out != t
	case []any:
		changed := false
		for i, e := range t {
			ne, c := walkStrings(e, fn)
			if c {
				t[i] = ne
				changed = true
			}
		}
		return t, changed
	case map[string]any:
		changed := false
		for k, e := range t {
			ne, c := walkStrings(e, fn)
			if c {
				t[k] = ne
				changed = true
			}
		}
		return t, changed
	default:
		return v, false
	}
}

// MapToolListDescriptions rewrites each tool's "description" field in a
// tools/list result via fn. Returns false if this is not a tools/list result.
func (m *Message) MapToolListDescriptions(fn func(string) string) (changed bool) {
	if len(m.Result) == 0 {
		return false
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(m.Result, &generic); err != nil {
		return false
	}
	rawTools, ok := generic["tools"]
	if !ok {
		return false
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return false
	}
	for i, t := range tools {
		var desc string
		if raw, ok := t["description"]; ok {
			_ = json.Unmarshal(raw, &desc)
		}
		out := fn(desc)
		if out != desc {
			encoded, err := json.Marshal(out)
			if err != nil {
				continue
			}
			tools[i]["description"] = encoded
			changed = true
		}
	}
	if !changed {
		return false
	}
	newTools, err := json.Marshal(tools)
	if err != nil {
		return false
	}
	generic["tools"] = newTools
	newResult, err := json.Marshal(generic)
	if err != nil {
		return false
	}
	m.Result = newResult
	return true
}

// Encode serializes the message back to a single line of JSON (no trailing
// newline). The proxy appends the newline delimiter.
func (m *Message) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// NewToolErrorResult builds a successful JSON-RPC response whose result carries
// isError:true and an explanatory text block. This is how a policy block is
// reported so the MCP client feeds the reason to the LLM instead of treating the
// server as crashed (see plan nuance #1). id is the raw id of the blocked request.
func NewToolErrorResult(id json.RawMessage, text string) *Message {
	result := map[string]any{
		"isError": true,
		"content": []map[string]string{
			{"type": "text", "text": text},
		},
	}
	encoded, _ := json.Marshal(result)
	return &Message{
		JSONRPC: "2.0",
		ID:      id,
		Result:  encoded,
	}
}

// NewError builds a genuine JSON-RPC protocol error. Reserved for internal proxy
// failures only — never for policy blocks.
func NewError(id json.RawMessage, code int, message string) *Message {
	return &Message{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &Error{Code: code, Message: message},
	}
}
