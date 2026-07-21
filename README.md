# mcp-guard 🛡️

[![Go Version](https://img.shields.io/github/go-mod/go-version/sainitish1609/mcp-guard)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **The local privacy firewall, secret sanitizer, and token compressor for AI coding agents.**

A security guardrail proxy for Model Context Protocol (MCP) servers.

![mcp-guard demo](assets/demo.gif)

`mcp-guard` is an ultra-fast, zero-dependency Go binary that sits transparently in the stdio JSON-RPC path between your editor (Claude Code, Cursor, VS Code) and any [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server.

It acts as a local security proxy—ensuring your sensitive API keys, database credentials, and protected paths (`~/.ssh`, `.env`, `.git`) are **never leaked to cloud LLMs** or mutated by autonomous tool execution.

---

## 💡 Why mcp-guard?

When AI agents run tools like `@modelcontextprotocol/server-filesystem` or `postgres-mcp`, they read raw files directly from your disk. If a file contains AWS keys, JWTs, or database passwords, **those credentials are sent directly to cloud AI APIs in plain text.**

`mcp-guard` runs locally on your machine to solve this without breaking agent execution:
- 🔒 **Zero-Trust Input/Output Inspection:** Intercepts both requests and responses on `stdin`/`stdout`.
- ⚡ **Zero-Dependency Go Binary:** Negligible performance overhead (< 1ms execution penalty).
- 🔄 **Recoverable Guardrail Errors:** Sends structured `isError: true` responses so AI agents can gracefully self-correct instead of crashing with transport failures.

---

## 🏗️ Architecture


```

┌─────────────────────────┐          ┌─────────────────────────┐          ┌─────────────────────────┐
│                         │          │                         │          │                         │
│  Editor / MCP Client    │  stdin   │        mcp-guard        │  stdin   │       MCP Server        │
│                         ├─────────►│                         ├─────────►│                         │
│  (Claude Code / Cursor) │          │  • Intercepts Writes    │          │  (e.g., filesystem,     │
│                         │  stdout  │  • Redacts Secrets      │  stdout  │   postgres, github)     │
│                         │◄─────────┤  • Compresses Context   │◄─────────┤                         │
└─────────────────────────┘          └─────────────────────────┘          └─────────────────────────┘

```

---

## ✨ Features

### 1. 🔑 Secret & Credential Redaction (Server ➔ Client)
Scans tool results for 10+ sensitive credential formats before they can reach the LLM:
* **Cloud & AI Keys:** AWS (`AKIA...`), Anthropic, OpenAI, Stripe, Google, GitHub PATs.
* **Database URIs:** Masks passwords in `postgres://user:pass@host`, `mongodb+srv://`, `redis://`.
* **Private Keys & JWTs:** Full block masking for RSA/PEM keys and Bearer tokens.

```env
# Before mcp-guard:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DATABASE_URL=postgres://admin:SuperSecret123!@db.internal:5432/prod

# After mcp-guard:
AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key]
DATABASE_URL=postgres://admin:[REDACTED:uri-credentials]@db.internal:5432/prod

```

### 2. 🛡️ Guardrail Policy & Write Protection (Client ➔ Server)

Prevents AI agents from modifying or reading protected paths, regardless of relative path traversal tricks (`../.ssh`):

* **Protected Paths:** `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `.git`, `.env*`
* **Sensitive Files:** `id_rsa`, `authorized_keys`, `.npmrc`, `.netrc`, `.pypirc`
* **Shell Script Blocking:** Blocks dangerous shell execution tools by default.

### 3. ⚡ Context Token Compression (Opt-In)

Strip redundant line/block comments and whitespace to save context window capacity.

> *Note: Compression automatically skips read-for-edit tools (`read_file`, `get_file_contents`) to preserve exact diff boundaries for safe file editing.*

---

## 🚀 Installation

```bash
# Install via Go
go install [github.com/sainitish1609/mcp-guard/cmd/mcp-guard@latest](https://github.com/sainitish1609/mcp-guard/cmd/mcp-guard@latest)

# Or build from source
git clone [https://github.com/sainitish1609/mcp-guard.git](https://github.com/sainitish1609/mcp-guard.git)
cd mcp-guard
go build -o mcp-guard ./cmd/mcp-guard

```

---

## ⚙️ Configuration & Integration

### Claude Code

Wrap any standard MCP server command using `mcp-guard --`:

```bash
claude mcp add postgres -- mcp-guard --redact-secrets --max-tokens 4000 -- npx -y @modelcontextprotocol/server-postgres

```

### Cursor / VS Code (`.vscode/mcp.json`)

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-guard",
      "args": [
        "--redact-secrets",
        "--block-shell",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/username/projects"
      ]
    }
  }
}

```

---

## 📋 Flag Reference

| Flag | Default | Description |
| --- | --- | --- |
| `--redact-secrets` | `true` | Mask API keys, tokens, and database passwords in tool responses |
| `--block-shell` | `true` | Block execution of shell scripts in exec tools |
| `--annotate-tools` | `true` | Append policy notices to `tools/list` so agents know boundaries upfront |
| `--compress` | `false` | Strip comments and blank lines from context (safe tools only) |
| `--max-tokens N` | `0` | Approximate token budget cap per result block (0 = unlimited) |
| `--protect-paths` | *(defaults)* | Custom comma-separated protected paths (overrides defaults) |
| `--log-level` | `info` | Set logging verbosity (`silent`, `error`, `info`, `debug` on **stderr**) |
| `--dry-run` | `false` | Log security events to stderr without mutating stdin/stdout |

---

## 🧪 Testing & Verification

```bash
# Run unit and integration tests
go test ./... -v

# Run static analysis
go vet ./...

```

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](https://www.google.com/search?q=LICENSE) for details.