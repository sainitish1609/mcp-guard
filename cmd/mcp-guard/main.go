// Command mcp-guard is a local-first security firewall and context compressor
// for MCP-based AI coding agents. It wraps a real MCP server, sitting in the
// stdio JSON-RPC path to redact secrets, block writes to protected paths and
// shell-script execution, and optionally compress oversized tool results.
//
// Usage:
//
//	mcp-guard [flags] -- <mcp-server-command> [args...]
//
// Example:
//
//	mcp-guard --redact-secrets --max-tokens 4000 -- npx -y @modelcontextprotocol/server-postgres
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
		fmt.Fprintf(os.Stderr, "Usage:\n  mcp-guard [flags] -- <mcp-server-command> [args...]\n\nFlags:\n")
		fs.PrintDefaults()
	}

	var (
		configPath    = fs.String("config", "", "path to a JSON config file (optional)")
		redactSecrets = fs.Bool("redact-secrets", true, "mask API keys/secrets in tool results")
		compress      = fs.Bool("compress", false, "strip comments/whitespace from tool results (see caveats)")
		maxTokens     = fs.Int("max-tokens", 0, "approx token cap per result block (0 = unlimited)")
		blockShell    = fs.Bool("block-shell", true, "block shell-script execution via exec-like tools")
		annotateTools = fs.Bool("annotate-tools", true, "append the mcp-guard policy notice to tools/list descriptions")
		protectPaths  = fs.String("protect-paths", "", "comma-separated protected paths (replaces defaults)")
		allowShell    = fs.String("allow-shell", "", "comma-separated allow-list substrings for shell commands")
		logLevel      = fs.String("log-level", "info", "log verbosity: silent|error|info|debug")
		dryRun        = fs.Bool("dry-run", false, "log what would be blocked/redacted without altering the stream")
	)

	if err := fs.Parse(guardArgs); err != nil {
		return 2
	}

	if len(childCmd) == 0 {
		fmt.Fprintln(os.Stderr, "error: no MCP server command given; expected `-- <command> [args...]`")
		fs.Usage()
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading config %q: %v\n", *configPath, err)
		return 2
	}

	// CLI flags override config-file/default values when explicitly set.
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	if setFlags["redact-secrets"] {
		cfg.RedactSecrets = *redactSecrets
	}
	if setFlags["compress"] {
		cfg.Compress = *compress
	}
	if setFlags["max-tokens"] {
		cfg.MaxTokens = *maxTokens
	}
	if setFlags["block-shell"] {
		cfg.BlockShell = *blockShell
	}
	if setFlags["annotate-tools"] {
		cfg.AnnotateTools = *annotateTools
	}
	if setFlags["protect-paths"] && *protectPaths != "" {
		cfg.ProtectPaths = splitCSV(*protectPaths)
	}
	if setFlags["allow-shell"] && *allowShell != "" {
		cfg.AllowShell = splitCSV(*allowShell)
	}
	if setFlags["log-level"] {
		cfg.LogLevel = config.LogLevel(*logLevel)
	}
	if setFlags["dry-run"] {
		cfg.DryRun = *dryRun
	}

	cfg.ExpandPaths()

	log := audit.New(cfg.LogLevel, cfg.DryRun)
	log.Startup(fmt.Sprintf("redact=%v compress=%v block-shell=%v annotate=%v max-tokens=%d child=%q",
		cfg.RedactSecrets, cfg.Compress, cfg.BlockShell, cfg.AnnotateTools, cfg.MaxTokens, strings.Join(childCmd, " ")))

	code, err := proxy.Run(context.Background(), cfg, log, childCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
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
