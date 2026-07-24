// Package config holds mcp-guard's runtime configuration: which protections are
// enabled, the protected-path list, token limits, and logging behavior. Values
// come from CLI flags, with an optional JSON config file supplying defaults.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// LogLevel controls audit verbosity.
type LogLevel string

const (
	LogSilent LogLevel = "silent"
	LogError  LogLevel = "error"
	LogInfo   LogLevel = "info"
	LogDebug  LogLevel = "debug"
)

// Config is the fully-resolved configuration handed to the proxy.
type Config struct {
	RedactSecrets       bool            `json:"redact_secrets"`
	EntropyScan         bool            `json:"entropy_scan"`
	EntropyMask         bool            `json:"entropy_mask"`
	ScanInjection       bool            `json:"scan_injection"`
	NeutralizeInjection bool            `json:"neutralize_injection"`
	ScanRequests        bool            `json:"scan_requests"`
	Compress            bool            `json:"compress"`
	MaxTokens           int             `json:"max_tokens"`
	BlockShell          bool            `json:"block_shell"`
	BlockSensitiveReads bool            `json:"block_sensitive_reads"`
	AnnotateTools       bool            `json:"annotate_tools"`
	RateLimit           int             `json:"rate_limit"` // tool calls/min, 0 = disabled
	ProtectPaths        []string        `json:"protect_paths"`
	ProtectNames        []string        `json:"protect_names"`
	ShellTools          []string        `json:"shell_tools"`
	AllowShell          []string        `json:"allow_shell"`
	CustomPatterns      []CustomPattern `json:"custom_patterns"`
	Stats               bool            `json:"stats"`
	PricePer1kTokens    float64         `json:"price_per_1k_tokens"`
	LogLevel            LogLevel        `json:"log_level"`
	LogFormat           string          `json:"log_format"` // "text" or "json"
	DryRun              bool            `json:"dry_run"`
}

// CustomPattern is a user-supplied secret regex with a label used in the mask.
type CustomPattern struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// defaultProtectPaths returns absolute/location-specific paths writes are
// blocked under. Home-relative entries (~) are expanded at load time. Name-based
// protections (e.g. any ".ssh" directory) live in defaultProtectNames instead.
func defaultProtectPaths() []string {
	return []string{
		"~/.config/gh",
		"~/.docker/config.json",
		"/etc",
	}
}

// defaultProtectNames returns sensitive path segments that are blocked wherever
// they appear in a write target — not only under the home directory. A segment
// matches if it equals the name exactly or begins with "<name>." (so ".env"
// also guards ".env.local", ".env.production", …).
func defaultProtectNames() []string {
	return []string{
		".ssh", ".aws", ".gnupg", ".kube", ".git", ".env",
		".npmrc", ".netrc", ".pypirc", ".dockercfg",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys",
	}
}

// defaultShellTools are tool-name substrings treated as shell execution.
func defaultShellTools() []string {
	return []string{"run", "shell", "exec", "command", "terminal", "bash", "process"}
}

// Default returns a Config with safe defaults: redaction and shell/path guarding
// on, compression off (see plan risk note), tool annotation on.
func Default() Config {
	return Config{
		RedactSecrets:       true,
		EntropyScan:         true,
		EntropyMask:         false, // audit-only by default; entropy is a hint, not a verdict
		ScanInjection:       true,
		NeutralizeInjection: true,
		ScanRequests:        true,
		Compress:            false,
		MaxTokens:           0,
		BlockShell:          true,
		BlockSensitiveReads: false,
		AnnotateTools:       true,
		RateLimit:           0,
		ProtectPaths:        defaultProtectPaths(),
		ProtectNames:        defaultProtectNames(),
		ShellTools:          defaultShellTools(),
		Stats:               true,
		PricePer1kTokens:    0.003, // rough blended input price; user-overridable
		LogLevel:            LogInfo,
		LogFormat:           "text",
	}
}

// ExpandPaths resolves ~ and returns cleaned absolute paths where possible.
// Relative entries (e.g. ".git", ".env") are kept as-is for suffix matching.
func (c *Config) ExpandPaths() {
	home, _ := os.UserHomeDir()
	out := make([]string, 0, len(c.ProtectPaths))
	for _, p := range c.ProtectPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "~") && home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
		if filepath.IsAbs(p) {
			p = filepath.Clean(p)
		}
		out = append(out, p)
	}
	c.ProtectPaths = out
}

// Load reads a JSON config file and overlays it onto Default(). A missing path
// argument yields Default(). Callers apply CLI flag overrides afterward.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
