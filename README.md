# mcp-guard

🛡️ Ultra-fast, local-first security firewall, secret sanitizer, and context-token
compressor for Claude Code, Cursor, VS Code/Copilot, and other MCP AI agents.

`mcp-guard` is a zero-dependency Go binary that wraps a real
[MCP](https://modelcontextprotocol.io) server and sits transparently in the stdio
JSON-RPC path between your editor and the tool. It never talks to the LLM provider
directly, so it works with **any** model your editor uses.

```
Editor (MCP client) ──stdin──►  mcp-guard  ──►  MCP server (e.g. npx postgres-mcp)
Editor (MCP client) ◄─stdout──  mcp-guard  ◄──  MCP server
```

## What it does

1. **Secret redaction** — scans tool/resource results (server → client) for API keys,
   `.env` values, private keys, JWTs, and cloud credentials, masking them as
   `[REDACTED:<type>]` before they can reach the LLM.
2. **Directory & shell guardrails** — inspects `tools/call` requests (client → server)
   and blocks writes to protected paths (`~/.ssh`, `~/.aws`, `.git`, `.env`, …) and
   shell-script execution. Blocks are returned as a normal MCP result with
   `isError: true`, so the agent sees *why* and can recover — not a transport error.
3. **Context compression** *(opt-in)* — strips comments/whitespace and can cap oversized
   results at an approximate token budget. Off by default; skips read-for-edit tools to
   avoid corrupting round-trip edits.
4. **Capability transparency** — appends a short policy notice to `tools/list`
   descriptions so the agent avoids restricted operations up front.

## Install

```bash
go install github.com/sainitish1609/mcp-guard/cmd/mcp-guard@latest
# or from source:
go build -o mcp-guard ./cmd/mcp-guard
```

## Usage

Wrap any MCP server launch command; everything after `--` is the server:

```bash
mcp-guard [flags] -- <mcp-server-command> [args...]
```

### Claude Code

```bash
claude mcp add postgres -- mcp-guard --redact-secrets --max-tokens 4000 -- npx -y @modelcontextprotocol/server-postgres
```

### VS Code / Cursor (`.vscode/mcp.json`)

```json
{
  "servers": {
    "database-tool": {
      "command": "mcp-guard",
      "args": ["--max-tokens", "4000", "--redact-secrets", "--", "npx", "-y", "@modelcontextprotocol/server-postgres"]
    }
  }
}
```

Once configured it runs silently — you interact with your editor exactly as before.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--redact-secrets` | `true` | Mask API keys/secrets in tool results |
| `--compress` | `false` | Strip comments/whitespace from results (see caveats) |
| `--max-tokens N` | `0` | Approx token cap per result block (0 = unlimited) |
| `--block-shell` | `true` | Block shell-script execution via exec-like tools |
| `--annotate-tools` | `true` | Append the policy notice to `tools/list` descriptions |
| `--protect-paths` | *(defaults)* | Comma-separated protected paths (replaces defaults) |
| `--allow-shell` | *(none)* | Comma-separated allow-list substrings for shell commands |
| `--config PATH` | *(none)* | JSON config file (flags override its values) |
| `--log-level` | `info` | `silent` \| `error` \| `info` \| `debug` (logged to **stderr**) |
| `--dry-run` | `false` | Log what would be blocked/redacted without altering the stream |

Audit output goes to **stderr**; **stdout** carries only the MCP protocol stream.

## Notes on compression

Compression is conservative and off by default. Altering a tool result that an agent will
later edit can corrupt its diff, so `--compress` skips read-for-edit tools
(`read_file`, `get_file_contents`, …) and only touches other results. It never modifies
string-literal contents.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```

## License

MIT — see [LICENSE](LICENSE).
