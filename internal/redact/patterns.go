package redact

import "regexp"

// Pattern is a named secret matcher.
//
// When maskGroup is 0 the entire match is replaced with [REDACTED:<Name>].
// When maskGroup > 0 only that submatch group is masked and the surrounding
// text is kept — used to preserve the variable name in `KEY=value` and the
// scheme/user in `postgres://user:pass@host`.
type Pattern struct {
	Name      string
	re        *regexp.Regexp
	maskGroup int
}

// builtinPatterns are compiled once at package init. Order matters for
// overlapping matches: specific high-confidence patterns run first so the
// generic env-secret/uri patterns don't clobber their labels.
var builtinPatterns = []Pattern{
	{Name: "aws-access-key", re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b`)},
	{Name: "github-token", re: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`)},
	{Name: "github-pat", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{Name: "anthropic-key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9\-_]{20,}\b`)},
	{Name: "openai-key", re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b`)},
	{Name: "google-api-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{Name: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{Name: "stripe-key", re: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`)},
	{Name: "private-key", re: regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{Name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	// Credentials embedded in a connection URI, e.g. postgres://user:password@host
	// or mongodb+srv://user:password@host. Masks only the password (group 2).
	{Name: "uri-credentials", re: regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*://[^:@/\s]+:)([^@/\s]+)(@)`), maskGroup: 2},
	// Generic KEY/TOKEN/SECRET/PASSWORD assignment (as in .env dumps or inline
	// prose). Masks only the value (group 3) so the variable name stays readable.
	// Unanchored so inline `FOO_PASSWORD=...` is caught too.
	{Name: "env-secret", re: regexp.MustCompile(`(?i)([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*\s*[:=]\s*)(["']?)([^\s"']+)(["']?)`), maskGroup: 3},
}
