package redact

import (
	"strings"
	"testing"
)

func TestEntropyCatchesUnknownKey(t *testing.T) {
	e := New(nil)
	e.EnableEntropy(true)
	// A generated-looking token matching no named pattern and with no secret
	// keyword nearby, so only the entropy pass can catch it.
	in := "session Xk9mQ2vBnR7wLp4sZa1cFd8gHj0tYu3E begins"
	got, hits := e.Scan(in)
	if strings.Contains(got, "Xk9mQ2vBnR7wLp4sZa1cFd8gHj0tYu3E") {
		t.Fatalf("high-entropy secret leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:high-entropy]") {
		t.Fatalf("expected high-entropy mask, got %q", got)
	}
	if len(hits) == 0 {
		t.Fatal("expected a hit")
	}
}

func TestEntropyIgnoresProseAndIdentifiers(t *testing.T) {
	e := New(nil)
	e.EnableEntropy(true)
	keep := []string{
		"The quick brown fox jumps over the lazy dog repeatedly today.",
		"3f8a1c9e2b7d4056f1a2b3c4d5e6f7a8b9c0d1e2",         // git SHA (hex only, 2 classes)
		"550e8400-e29b-41d4-a716-446655440000",             // UUID (hex only)
		"internal/redact/entropy_test_helper_file",         // path-ish, low entropy
		"/Users/parvezlasi/mcp-guard-sandbox/poisoned.txt", // absolute path w/ mixed case
		"/home/CamelCase/some-project/src/MainModule.go",   // another mixed-case path
	}
	for _, in := range keep {
		got, _ := e.Scan(in)
		if strings.Contains(got, "high-entropy") {
			t.Fatalf("false positive on %q -> %q", in, got)
		}
	}
}

func TestEntropyOffByDefault(t *testing.T) {
	e := New(nil)
	in := "session Xk9mQ2vBnR7wLp4sZa1cFd8gHj0tYu3E begins"
	got, _ := e.Scan(in)
	if strings.Contains(got, "high-entropy") {
		t.Fatalf("entropy should be off unless enabled: %q", got)
	}
}
