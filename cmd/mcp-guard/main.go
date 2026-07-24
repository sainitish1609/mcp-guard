// Command mcp-guard is a local-first security firewall and context compressor
// for MCP-based AI coding agents. It wraps a real MCP server, sitting in the
// JSON-RPC path to redact secrets, defend against prompt injection, block writes
// to protected paths and shell-script execution, throttle runaway agents, and
// optionally compress oversized tool results.
//
// Usage (stdio):
//
//	mcp-guard [flags] -- <mcp-server-command> [args...]
//
// Usage (remote HTTP/SSE server):
//
//	mcp-guard [flags] --http-listen :8080 --http-upstream https://host/mcp
//
// Example:
//
//	mcp-guard --profile strict --max-tokens 4000 -- npx -y @modelcontextprotocol/server-postgres
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sainitish1609/mcp-guard/internal/audit"
	"github.com/sainitish1609/mcp-guard/internal/config"
	"github.com/sainitish1609/mcp-guard/internal/proxy"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	guardArgs, childCmd := splitArgs(argv)

	fs := flag.NewFlagSet("mcp-guard", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "mcp-guard — security firewall + context compressor for MCP agents\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  mcp-guard [flags] -- <mcp-server-command> [args...]\n")
		fmt.Fprintf(os.Stderr, "  mcp-guard [flags] --http-listen :8080 --http-upstream https://host/mcp\n\nFlags:\n")
		fs.PrintDefaults()
	}

	var (
		configPath    = fs.String("config", "", "path to a JSON config file (optional)")
		profile       = fs.String("profile", "", "policy preset: strict|standard|permissive")
		redactSecrets = fs.Bool("redact-secrets", true, "mask API keys/secrets in tool results")
		entropyScan   = fs.Bool("entropy-scan", true, "also mask high-entropy tokens that match no known pattern")
		scanInjection = fs.Bool("scan-injection", true, "strip hidden Unicode and neutralize prompt-injection directives")
		neutralize    = fs.Bool("neutralize-injection", true, "rewrite detected injection directives (off = detect+log only)")
		scanRequests  = fs.Bool("scan-requests", true, "warn when outbound tool-call arguments contain secrets")
		compress      = fs.Bool("compress", false, "strip comments/whitespace from tool results (see caveats)")
		maxTokens     = fs.Int("max-tokens", 0, "approx token cap per result block (0 = unlimited)")
		blockShell    = fs.Bool("block-shell", true, "block shell-script execution via exec-like tools")
		blockReads    = fs.Bool("block-sensitive-reads", false, "block reads of protected paths (default: allow + redact)")
		annotateTools = fs.Bool("annotate-tools", true, "append the mcp-guard policy notice to tools/list descriptions")
		rateLimit     = fs.Int("rate-limit", 0, "max tool calls/min before throttling (0 = disabled)")
		protectPaths  = fs.String("protect-paths", "", "comma-separated protected paths (replaces defaults)")
		protectNames  = fs.String("protect-names", "", "comma-separated protected path segments (replaces defaults)")
		allowShell    = fs.String("allow-shell", "", "comma-separated allow-list substrings for shell commands")
		stats         = fs.Bool("stats", true, "print a session summary on exit and on SIGUSR1")
		price         = fs.Float64("price-per-1k", 0.003, "USD per 1K tokens for the cost-saved estimate")
		logLevel      = fs.String("log-level", "info", "log verbosity: silent|error|info|debug")
		logFormat     = fs.String("log-format", "text", "log format: text|json (JSON Lines)")
		dryRun        = fs.Bool("dry-run", false, "log what would be blocked/redacted without altering the stream")
		httpListen    = fs.String("http-listen", "", "run as an HTTP/SSE proxy on this address (e.g. :8080)")
		httpUpstream  = fs.String("http-upstream", "", "upstream MCP server URL for HTTP/SSE mode")
	)

	if err := fs.Parse(guardArgs); err != nil {
		return 2
	}

	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	// resolve builds the fully-effective config: defaults ← config file ←
	// profile ← explicitly-set CLI flags. It is reused on SIGHUP reloads.
	resolve := func() (config.Config, error) {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return cfg, fmt.Errorf("loading config %q: %w", *configPath, err)
		}
		if *profile != "" {
			if !cfg.ApplyProfile(*profile) {
				return cfg, fmt.Errorf("unknown profile %q (known: %s)", *profile, strings.Join(config.KnownProfiles(), ", "))
			}
		}
		applyOverride(setFlags, "redact-secrets", func() { cfg.RedactSecrets = *redactSecrets })
		applyOverride(setFlags, "entropy-scan", func() { cfg.EntropyScan = *entropyScan })
		applyOverride(setFlags, "scan-injection", func() { cfg.ScanInjection = *scanInjection })
		applyOverride(setFlags, "neutralize-injection", func() { cfg.NeutralizeInjection = *neutralize })
		applyOverride(setFlags, "scan-requests", func() { cfg.ScanRequests = *scanRequests })
		applyOverride(setFlags, "compress", func() { cfg.Compress = *compress })
		applyOverride(setFlags, "max-tokens", func() { cfg.MaxTokens = *maxTokens })
		applyOverride(setFlags, "block-shell", func() { cfg.BlockShell = *blockShell })
		applyOverride(setFlags, "block-sensitive-reads", func() { cfg.BlockSensitiveReads = *blockReads })
		applyOverride(setFlags, "annotate-tools", func() { cfg.AnnotateTools = *annotateTools })
		applyOverride(setFlags, "rate-limit", func() { cfg.RateLimit = *rateLimit })
		applyOverride(setFlags, "stats", func() { cfg.Stats = *stats })
		applyOverride(setFlags, "price-per-1k", func() { cfg.PricePer1kTokens = *price })
		applyOverride(setFlags, "log-level", func() { cfg.LogLevel = config.LogLevel(*logLevel) })
		applyOverride(setFlags, "log-format", func() { cfg.LogFormat = *logFormat })
		applyOverride(setFlags, "dry-run", func() { cfg.DryRun = *dryRun })
		if setFlags["protect-paths"] && *protectPaths != "" {
			cfg.ProtectPaths = splitCSV(*protectPaths)
		}
		if setFlags["protect-names"] && *protectNames != "" {
			cfg.ProtectNames = splitCSV(*protectNames)
		}
		if setFlags["allow-shell"] && *allowShell != "" {
			cfg.AllowShell = splitCSV(*allowShell)
		}
		cfg.ExpandPaths()
		return cfg, nil
	}

	cfg, err := resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	log := audit.New(cfg.LogLevel, cfg.DryRun)
	if cfg.LogFormat == "json" {
		log.SetJSON(true)
	}

	// HTTP/SSE mode: no child process, forward to a remote MCP endpoint.
	if *httpUpstream != "" || *httpListen != "" {
		listen := *httpListen
		if listen == "" {
			listen = ":8080"
		}
		log.Startup(fmt.Sprintf("mode=http redact=%v inject=%v rate-limit=%d upstream=%s",
			cfg.RedactSecrets, cfg.ScanInjection, cfg.RateLimit, *httpUpstream))
		if err := proxy.RunHTTP(context.Background(), cfg, log, listen, *httpUpstream, resolve); err != nil {
			fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
			return 1
		}
		return 0
	}

	if len(childCmd) == 0 {
		fmt.Fprintln(os.Stderr, "error: no MCP server command given; expected `-- <command> [args...]` or --http-upstream")
		fs.Usage()
		return 2
	}

	log.Startup(fmt.Sprintf("redact=%v entropy=%v inject=%v compress=%v block-shell=%v block-reads=%v rate-limit=%d max-tokens=%d child=%q",
		cfg.RedactSecrets, cfg.EntropyScan, cfg.ScanInjection, cfg.Compress, cfg.BlockShell, cfg.BlockSensitiveReads, cfg.RateLimit, cfg.MaxTokens, strings.Join(childCmd, " ")))

	code, err := proxy.Run(context.Background(), cfg, log, childCmd, resolve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// applyOverride runs set() only if the named flag was explicitly provided.
func applyOverride(setFlags map[string]bool, name string, set func()) {
	if setFlags[name] {
		set()
	}
}

// splitArgs divides argv at the first "--" separator into mcp-guard's own flags
// and the child MCP server command.
func splitArgs(argv []string) (guardArgs, childCmd []string) {
	for i, a := range argv {
		if a == "--" {
			return argv[:i], argv[i+1:]
		}
	}
	return argv, nil
}

// splitCSV splits and trims a comma-separated list, dropping empties.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
