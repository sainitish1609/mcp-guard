package redact

import (
	"strings"
	"testing"

	"github.com/sainitish1609/mcp-guard/internal/config"
)

func TestScanMasksKnownSecrets(t *testing.T) {
	e := New(nil)
	cases := []struct {
		name string
		in   string
		want string // substring expected in masked output
	}{
		{"aws", "key AKIAIOSFODNN7EXAMPLE here", "[REDACTED:aws-access-key]"},
		{"github", "tok ghp_" + strings.Repeat("a", 36) + " end", "[REDACTED:github-token]"},
		{"anthropic", "sk-ant-api03-" + strings.Repeat("x", 30), "[REDACTED:anthropic-key]"},
		{"google", "AIza" + strings.Repeat("b", 35), "[REDACTED:google-api-key]"},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "[REDACTED:jwt]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, hits := e.Scan(c.in)
			if !strings.Contains(got, c.want) {
				t.Fatalf("expected %q in output, got %q", c.want, got)
			}
			if len(hits) == 0 {
				t.Fatalf("expected at least one hit")
			}
		})
	}
}

func TestScanEnvSecretPreservesKey(t *testing.T) {
	e := New(nil)
	in := "DB_PASSWORD=hunter2secretvalue\nHOST=localhost"
	got, hits := e.Scan(in)
	if !strings.Contains(got, "DB_PASSWORD=[REDACTED:env-secret]") {
		t.Fatalf("expected key preserved with masked value, got %q", got)
	}
	if strings.Contains(got, "hunter2secretvalue") {
		t.Fatalf("secret value leaked: %q", got)
	}
	if !strings.Contains(got, "HOST=localhost") {
		t.Fatalf("non-secret assignment should be untouched, got %q", got)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 env-secret hit, got %d", len(hits))
	}
}

func TestScanEnvSecretInlineProse(t *testing.T) {
	e := New(nil)
	in := "connected with DB_PASSWORD=supersecret123 to the host"
	got, hits := e.Scan(in)
	if strings.Contains(got, "supersecret123") {
		t.Fatalf("inline secret value leaked: %q", got)
	}
	if !strings.Contains(got, "DB_PASSWORD=[REDACTED:env-secret]") {
		t.Fatalf("expected inline env-secret masked with key preserved, got %q", got)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
}

func TestScanURICredentials(t *testing.T) {
	e := New(nil)
	cases := []struct {
		in     string
		secret string // must not appear in output
		keep   string // must still appear (scheme/user/host preserved)
	}{
		{"postgres://admin:s3cr3tpw@db.internal:5432/app", "s3cr3tpw", "postgres://admin:"},
		{"mongodb+srv://user:my-pass@cluster0.mongodb.net/test", "my-pass", "@cluster0.mongodb.net"},
		{"redis://default:hunter2@cache:6379", "hunter2", "redis://default:"},
	}
	for _, c := range cases {
		got, hits := e.Scan(c.in)
		if strings.Contains(got, c.secret) {
			t.Fatalf("uri password leaked: %q", got)
		}
		if !strings.Contains(got, "[REDACTED:uri-credentials]") {
			t.Fatalf("expected uri password masked, got %q", got)
		}
		if !strings.Contains(got, c.keep) {
			t.Fatalf("expected %q preserved, got %q", c.keep, got)
		}
		if len(hits) == 0 {
			t.Fatalf("expected a hit for %q", c.in)
		}
	}
}

// Bug A: a password containing '@' must be masked in full, not split on the
// first '@' leaving the tail visible.
func TestScanURIPasswordWithAtSign(t *testing.T) {
	e := New(nil)
	in := "postgres://app_admin:P@ssw0rd123!@db.internal.net:5432/prod"
	got, _ := e.Scan(in)
	if strings.Contains(got, "ssw0rd123") || strings.Contains(got, "P@ss") {
		t.Fatalf("password with '@' partially leaked: %q", got)
	}
	want := "postgres://app_admin:[REDACTED:uri-credentials]@db.internal.net:5432/prod"
	if got != want {
		t.Fatalf("unexpected masking:\n got %q\nwant %q", got, want)
	}
}

// Bug B: user-less URIs (redis://:password@host) must still match.
func TestScanURIEmptyUsername(t *testing.T) {
	e := New(nil)
	in := "redis://:RedisAuthToken_98765@redis.internal.net:6379/0"
	got, hits := e.Scan(in)
	if strings.Contains(got, "RedisAuthToken_98765") {
		t.Fatalf("user-less redis password leaked: %q", got)
	}
	want := "redis://:[REDACTED:uri-credentials]@redis.internal.net:6379/0"
	if got != want {
		t.Fatalf("unexpected masking:\n got %q\nwant %q", got, want)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
}

func TestScanPrivateKeyBlock(t *testing.T) {
	e := New(nil)
	in := "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----\nafter"
	got, _ := e.Scan(in)
	if strings.Contains(got, "MIIEabc") {
		t.Fatalf("private key body leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:private-key]") {
		t.Fatalf("expected private-key mask, got %q", got)
	}
}

func TestSpecificPatternNotClobberedByEnvSecret(t *testing.T) {
	e := New(nil)
	// The value is a real AWS key inside a KEY= assignment; the specific
	// aws-access-key label must survive, not be overwritten by env-secret.
	got, hits := e.Scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
	if !strings.Contains(got, "[REDACTED:aws-access-key]") {
		t.Fatalf("expected specific aws label preserved, got %q", got)
	}
	if strings.Contains(got, "env-secret") {
		t.Fatalf("env-secret clobbered the specific label: %q", got)
	}
	for _, h := range hits {
		if h.Pattern == "env-secret" {
			t.Fatalf("env-secret should not have fired on an already-masked value: %+v", hits)
		}
	}
}

func TestScanCleanTextUntouched(t *testing.T) {
	e := New(nil)
	in := "func add(a, b int) int { return a + b }"
	got, hits := e.Scan(in)
	if got != in {
		t.Fatalf("clean text altered: %q", got)
	}
	if hits != nil {
		t.Fatalf("expected no hits, got %v", hits)
	}
}

func TestCustomPattern(t *testing.T) {
	e := New([]config.CustomPattern{{Name: "internal-id", Regex: "INTERNAL-[0-9]{6}"}})
	got, hits := e.Scan("ref INTERNAL-123456 done")
	if !strings.Contains(got, "[REDACTED:internal-id]") {
		t.Fatalf("custom pattern not applied: %q", got)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
}
