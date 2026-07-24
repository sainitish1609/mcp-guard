package redact

import (
	"strings"
	"testing"
)

func TestEntropyAuditOnlyByDefault(t *testing.T) {
	e := New(nil)
	e.EnableEntropy(true) // detection on, masking NOT opted in
	in := "session Xk9mQ2vBnR7wLp4sZa1cFd8gHj0tYu3E begins"
	got, hits := e.Scan(in)
	// Audit-only: the payload must be UNCHANGED...
	if got != in {
		t.Fatalf("audit-only mode must not mask, got %q", got)
	}
	// ...but the finding must still be reported, flagged as Audit, with offsets.
	if len(hits) != 1 || hits[0].Pattern != "high-entropy" {
		t.Fatalf("expected one high-entropy hit, got %+v", hits)
	}
	if !hits[0].Audit {
		t.Fatal("entropy hit should be marked Audit in audit-only mode")
	}
	if len(hits[0].Spans) != 1 {
		t.Fatalf("expected one span, got %+v", hits[0].Spans)
	}
	s := hits[0].Spans[0]
	if in[s[0]:s[1]] != "Xk9mQ2vBnR7wLp4sZa1cFd8gHj0tYu3E" {
		t.Fatalf("span does not cover the token: %q", in[s[0]:s[1]])
	}
}

func TestEntropyMasksWhenOptedIn(t *testing.T) {
	e := New(nil)
	e.EnableEntropy(true)
	e.SetEntropyMask(true)
	in := "session Xk9mQ2vBnR7wLp4sZa1cFd8gHj0tYu3E begins"
	got, hits := e.Scan(in)
	if strings.Contains(got, "Xk9mQ2vBnR7wLp4sZa1cFd8gHj0tYu3E") {
		t.Fatalf("secret leaked with masking on: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:high-entropy]") {
		t.Fatalf("expected mask, got %q", got)
	}
	if len(hits) != 1 || hits[0].Audit {
		t.Fatalf("masked hit must not be Audit: %+v", hits)
	}
}

// The commenter's cases: these legitimately trip the entropy heuristic. In the
// default audit-only mode they must be FLAGGED but never MASKED, so structured
// data is not silently corrupted.
func TestEntropyFalsePositivesAuditedNotMasked(t *testing.T) {
	e := New(nil)
	e.EnableEntropy(true) // default audit-only
	fps := []string{
		"sha512-Uu7wPT0k1vpFEUvKXPQBnpuwFCUxYX3aXvcS8fSlXB7pKZlkZAHcgSDF1IB6TjaGqQOtG68V0F3Cn7XVEdAA==",
		"dGhpcyBpcyBhIGxvbmcgYmFzZTY0IGZpeHR1cmUgdmFsdWU=",
		"X-Amz-Signature=b1f2c3D4e5F6a7089A1b2C3d4E5f6071",
	}
	for _, in := range fps {
		got, hits := e.Scan(in)
		if got != in {
			t.Fatalf("audit-only must not alter %q -> %q", in, got)
		}
		// It's fine (expected) that these are flagged — the point is they aren't masked.
		for _, h := range hits {
			if h.Pattern == "high-entropy" && !h.Audit {
				t.Fatalf("false-positive %q was masked, not audited", in)
			}
		}
	}
}

func TestEntropyIgnoresProseAndIdentifiers(t *testing.T) {
	e := New(nil)
	e.EnableEntropy(true)
	e.SetEntropyMask(true) // even in mask mode, these must not be flagged at all
	keep := []string{
		"The quick brown fox jumps over the lazy dog repeatedly today.",
		"3f8a1c9e2b7d4056f1a2b3c4d5e6f7a8b9c0d1e2",         // git SHA (hex only, 2 classes)
		"550e8400-e29b-41d4-a716-446655440000",             // UUID (hex only)
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
	e := New(nil) // EnableEntropy not called
	in := "session Xk9mQ2vBnR7wLp4sZa1cFd8gHj0tYu3E begins"
	got, hits := e.Scan(in)
	if got != in || len(hits) != 0 {
		t.Fatalf("entropy should be inert unless enabled: %q %+v", got, hits)
	}
}
