package config

import "testing"

func TestApplyProfileStrict(t *testing.T) {
	c := Default()
	if !c.ApplyProfile("strict") {
		t.Fatal("strict should be a known profile")
	}
	if !c.BlockSensitiveReads {
		t.Fatal("strict must block sensitive reads")
	}
	if c.RateLimit == 0 {
		t.Fatal("strict must set a rate limit")
	}
}

func TestApplyProfilePermissive(t *testing.T) {
	c := Default()
	c.ApplyProfile("permissive")
	if c.BlockShell {
		t.Fatal("permissive should relax shell blocking")
	}
	if !c.RedactSecrets {
		t.Fatal("permissive must still redact secrets")
	}
	if c.NeutralizeInjection {
		t.Fatal("permissive should only detect injection, not neutralize")
	}
}

func TestApplyProfileUnknown(t *testing.T) {
	c := Default()
	if c.ApplyProfile("bogus") {
		t.Fatal("unknown profile should return false")
	}
}
