package config

// Profiles are named policy presets that let one mcp-guard binary apply
// different strictness to different servers — e.g. a locked-down profile for a
// shell/exec server and a relaxed one for a read-only docs server. A profile is
// applied on top of Default() before the JSON config file and CLI flags, so
// those still win where set.
//
// Built-in profiles:
//
//	strict     — maximum protection: block sensitive reads, entropy on, tight
//	             rate limit, injection neutralized. For powerful/untrusted servers.
//	standard   — the balanced defaults (same as Default()).
//	permissive — keep redaction + injection defense, but relax write/read/shell
//	             guards and rate limiting. For trusted, read-only servers.

// ApplyProfile mutates c according to the named profile. An unknown or empty
// name leaves c unchanged and returns false.
func (c *Config) ApplyProfile(name string) bool {
	switch name {
	case "", "standard":
		return name == "standard"
	case "strict":
		c.RedactSecrets = true
		c.EntropyScan = true
		c.ScanInjection = true
		c.NeutralizeInjection = true
		c.ScanRequests = true
		c.BlockShell = true
		c.BlockSensitiveReads = true
		c.AnnotateTools = true
		if c.RateLimit == 0 {
			c.RateLimit = 120
		}
		return true
	case "permissive":
		c.RedactSecrets = true
		c.EntropyScan = false
		c.ScanInjection = true
		c.NeutralizeInjection = false // detect-only
		c.ScanRequests = false
		c.BlockShell = false
		c.BlockSensitiveReads = false
		c.RateLimit = 0
		return true
	default:
		return false
	}
}

// KnownProfiles lists the built-in profile names for help text and validation.
func KnownProfiles() []string { return []string{"strict", "standard", "permissive"} }
