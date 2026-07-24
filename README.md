# mcp-guard 🛡️

[![CI](https://github.com/sainitish1609/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/sainitish1609/mcp-guard/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sainitish1609/mcp-guard)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](go.mod)
[![Transport](https://img.shields.io/badge/transport-stdio%20%2B%20HTTP%2FSSE-blue.svg)](#-http--sse-remote-servers)

> **The local privacy firewall, prompt-injection shield, secret sanitizer, and token compressor for AI coding agents.**

A zero-dependency security proxy for Model Context Protocol (MCP) servers.

![mcp-guard demo](assets/demo.gif)

`mcp-guard` is an ultra-fast, zero-dependency Go binary that sits transparently between your editor (Claude Code, Cursor, VS Code, Copilot) and any [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server — over **stdio** or **HTTP/SSE**.

It ensures your API keys, database credentials, and protected paths (`~/.ssh`, `.env`, `.git`) are **never leaked to cloud LLMs**, that malicious content **cannot hijack your agent**, and that autonomous tool execution **cannot touch what it shouldn't** — all while trimming token spend.

---

## 💡 Why mcp-guard?

When AI agents run tools like `@modelcontextprotocol/server-filesystem` or `postgres-mcp`, they read raw files and query results straight off your machine. Three things go wrong:

1. **Secrets leak.** A file with AWS keys, JWTs, or DB passwords gets shipped verbatim to a cloud LLM.
2. **Agents get hijacked.** A file or web page can carry *hidden instructions* — invisible Unicode or "ignore all previous instructions" — that the model obeys (prompt injection / tool poisoning).
3. **Agents overreach.** An autonomous agent overwrites `~/.ssh/authorized_keys`, pipes `curl … | bash`, or reads 100 files in a burst.

`mcp-guard` runs **locally** and fixes all three without breaking agent execution:

- 🔒 **Zero-Trust I/O Inspection** — intercepts both requests and responses on every transport.
- ⚡ **Zero-Dependency Go Binary** — pure standard library, sub-millisecond overhead.
- 🔄 **Recoverable Guardrail Errors** — returns structured `isError: true` results so agents self-correct instead of crashing.
- 📊 **Visible Value** — a session summary shows exactly what it protected and how many tokens/dollars it saved.

---

## 🎯 Threat Model — what this does and doesn't replace

`mcp-guard` is **defense-in-depth for the agent boundary**, not a replacement for good security hygiene. Being precise about that matters more than sounding impressive.

**What it addresses**

| Risk | How `mcp-guard` handles it |
| --- | --- |
| Sensitive data leaving your machine when an agent reads a file or query result | Redacted before it reaches the model |
| Instructions injected into content your agent consumes (files, web pages, **tool descriptions**) | Hidden Unicode stripped, directives neutralized |
| An agent writing to paths it was never meant to touch | Blocked, including via `../` traversal and symlinks |
| A runaway or compromised agent enumerating your filesystem | Rate-limited, read-bursts flagged |
| No record of any of the above | Every action audited to stderr (text or JSON Lines) |

**What it explicitly does _not_ replace**

- **Short-lived credentials.** If you can use STS / OIDC federation / SSO, do that first — it is the stronger control. Rotation shrinks the blast radius; `mcp-guard` reduces the chance of disclosure in the first place. They solve different halves, and the credential fix is the more important one.
- **A secrets manager or least-privilege IAM.** A key that was never on disk cannot be read off disk.
- **Reviewing what your agent actually does.** Guardrails constrain the blast radius; they do not make an unreviewed agent trustworthy.

**Known limitations — read these before relying on it**

- **Detection is heuristic.** Named-pattern secret matching is high-precision and masks by default; the entropy catch-all is lower-precision (it fires on integrity hashes and base64 fixtures) so it is **audit-only by default** and only masks when you opt in. Injection detection is signature-based. A novel credential format or a carefully-worded injection *will* get through — treat it as a layer, not a guarantee.
- **It only sees traffic that flows through it.** An MCP server that makes its own outbound network calls (a `fetch`-style server, telemetry, a phone-home) is invisible to `mcp-guard`. It secures the client↔server channel, not the server's own egress.
- **Request-side secret scanning warns, it does not block.** Some tools legitimately need credentials in their arguments, so blocking by default would break them.
- **Compression can alter text.** It is off by default and skips read-for-edit tools, because rewriting a file the agent is about to patch corrupts the diff.
- **It does not authenticate the MCP server.** A malicious server can still return wrong (if sanitized) answers. Injection defense reduces that risk; it does not eliminate it.

> If you find a case where a real secret or injection payload slips through, that is a bug worth [opening an issue](https://github.com/sainitish1609/mcp-guard/issues) for — false negatives and false positives are both regressions.

---

## 🏗️ Architecture

```
┌─────────────────────────┐          ┌────────────────────────────────────┐          ┌─────────────────────────┐
│                         │  request │             mcp-guard              │  request │                         │
│  Editor / MCP Client    ├─────────►│  ┌──────────────────────────────┐  ├─────────►│       MCP Server        │
│                         │          │  │ →  guardrails · shell block   │  │          │  (filesystem, postgres, │
│  (Claude Code / Cursor  │          │  │    rate-limit · req-secrets   │  │          │   github, http, …)      │
│   / VS Code / Copilot)  │◄─────────┤  │ ←  redact · entropy · inject  │  │◄─────────┤                         │
│                         │ response │  │    defense · compression      │  │ response │                         │
└─────────────────────────┘          │  └──────────────────────────────┘  │          └─────────────────────────┘
                                      │   stdio  ·  HTTP / SSE  ·  audit    │
                                      └────────────────────────────────────┘
```

---

## ✨ Features

### 1. 🔑 Secret & Credential Redaction (Server ➔ Client)
Scans **every string** in a tool result — including `structuredContent` mirrors and tool descriptions — for 12+ credential formats before they reach the LLM:
* **Cloud & AI keys:** AWS (`AKIA…`), Anthropic, OpenAI, Stripe, Google, Slack, GitHub PATs.
* **Database URIs:** masks the password in `postgres://user:pass@host`, `mongodb+srv://`, `redis://:pass@host` — even passwords containing `@`.
* **Private keys & JWTs:** full-block masking for RSA/PEM keys and Bearer tokens.
* **🆕 High-entropy catch-all (audit-only by default):** a Shannon-entropy pass flags *unknown-format* generated secrets that match no named pattern, using a character-class discriminator to avoid git SHAs, UUIDs, and file paths. Because the heuristic also fires on integrity hashes, base64 fixtures, and signed URLs, it **reports** by default (logging the detector and byte offsets) and only masks when you opt in with `--entropy-mask` or `--profile strict`. This keeps it from silently corrupting otherwise-valid structured data.

```env
# Before mcp-guard:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DATABASE_URL=postgres://admin:P@ssw0rd123!@db.internal:5432/prod
SESSION=nQ7wLp4sZa1cFd8gHj0tYuXk9mR2vB3E

# After mcp-guard:
AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key]
DATABASE_URL=postgres://admin:[REDACTED:uri-credentials]@db.internal:5432/prod
SESSION=[REDACTED:high-entropy]   # entropy match — masked under --entropy-mask / --profile strict;
                                  # audit-only (logged, not masked) by default
```

### 2. 🧬 Prompt-Injection & Tool-Poisoning Defense 🆕
Content coming back from a server (file bodies, web pages, even a **malicious server's own tool descriptions**) can carry instructions aimed at your agent. mcp-guard neutralizes both vectors:
* **Hidden Unicode** — strips invisible "tag" characters (`U+E0000` block used to smuggle invisible ASCII), bidirectional-override controls, and zero-width spaces. Legitimate script/emoji joiners are preserved.
* **Injection directives** — high-signal phrases like *"ignore all previous instructions"*, *"do not tell the user"*, or *"reveal your system prompt"* are replaced with a visible `[mcp-guard: neutralized-injection]` marker (or detect-only, your choice).

### 3. 🛡️ Directory Guardrails & Write Protection (Client ➔ Server)
Blocks agents from modifying protected paths — through relative traversal (`../.ssh`) **and symlink escapes** 🆕 (a `project/data → ~/.ssh` link is resolved and caught):
* **Protected directories (anywhere in the path):** `~/.ssh`, `.aws`, `.gnupg`, `.kube`, `.git`, `.env*`
* **Sensitive files:** `id_rsa`, `id_ed25519`, `authorized_keys`, `.npmrc`, `.netrc`, `.pypirc`, `.dockercfg`
* **Shell-script blocking:** refuses `*.sh`/`*.ps1`, `bash -c`, and `curl … | sh` patterns by default.
* **🆕 Optional sensitive-read blocking:** hard-block *reads* of protected paths (default: allow the read and redact its contents instead).

### 4. 🚦 Exfiltration & Anomaly Guardrails 🆕
A behavioral layer on top of per-call checks:
* **Rate limiting** — throttle runaway or compromised agents past a calls-per-minute cap.
* **Read-burst detection** — warns on a sudden spike of distinct file reads (a classic bulk-exfiltration signature).
* **Outbound secret scanning** — warns when a *tool call's arguments* carry secret-shaped data, so a key the agent just read can't silently be forwarded to a phone-home server unnoticed.

### 5. ⚡ Context Token Compression (Opt-In)
Strips redundant comments and whitespace to save context-window capacity, with a code-aware token estimator for accurate accounting.
> *Compression automatically skips read-for-edit tools (`read_file`, `get_file_contents`) to preserve exact diff boundaries for safe file editing.*

### 6. 📊 Session Summary & Structured Audit 🆕
* On exit (and on `SIGUSR1`) mcp-guard prints a **summary**: secrets redacted by type, writes/reads/shell blocked, injections neutralized, tokens saved, and an **estimated `$` saved**.
* All activity streams to **stderr** as human text or **JSON Lines** (`--log-format json`) for SIEM ingestion. stdout carries only the MCP protocol.

```
mcp-guard session summary
  secrets redacted       4
      aws-access-key     1
      uri-credentials    1
      high-entropy       2
  writes blocked         1
  injections neutralized 3
  tokens saved           1840
  est. cost saved        $0.0055
```

### 7. 🎛️ Policy Profiles & Hot Reload 🆕
* **Profiles** apply per-server strictness in one flag: `--profile strict|standard|permissive` (e.g. lock down a shell server, relax a read-only docs server).
* **Hot reload** — send `SIGHUP` to re-read the config and swap policy live, without dropping the agent connection.

---

## 🚀 Installation

**Prebuilt binary** (no Go toolchain required) — grab it from the [latest release](https://github.com/sainitish1609/mcp-guard/releases/latest):

```bash
# macOS (Apple Silicon) — swap darwin_arm64 for your platform
curl -sSL https://github.com/sainitish1609/mcp-guard/releases/latest/download/mcp-guard_darwin_arm64.tar.gz | tar xz
sudo mv mcp-guard /usr/local/bin/
```

**With Go:**

```bash
go install github.com/sainitish1609/mcp-guard/cmd/mcp-guard@latest
```

**From source:**

```bash
git clone https://github.com/sainitish1609/mcp-guard.git
cd mcp-guard
go build -o mcp-guard ./cmd/mcp-guard
```

Builds for macOS, Linux, and Windows (amd64 + arm64). Every protection works on all
platforms; the `SIGHUP`/`SIGUSR1` signal hooks are Unix-only, and the end-of-session
summary still prints on exit everywhere.

---

## ⚙️ Configuration & Integration

### Claude Code

Wrap any standard MCP server command using `mcp-guard --`:

```bash
claude mcp add postgres -- mcp-guard --profile strict --max-tokens 4000 -- npx -y @modelcontextprotocol/server-postgres
```

### Cursor / VS Code (`.vscode/mcp.json`)

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-guard",
      "args": [
        "--redact-secrets",
        "--scan-injection",
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

### 🌐 HTTP / SSE (remote servers)

Protect a **remote** MCP server that speaks Streamable-HTTP/SSE — same pipeline, no child process:

```bash
mcp-guard --profile strict --http-listen :8080 --http-upstream https://my-mcp-host.example/mcp
```

Point your client at `http://localhost:8080` and every JSON and SSE message is inspected in flight.

---

## 📋 Flag Reference

| Flag | Default | Description |
| --- | --- | --- |
| `--profile` | *(none)* | Policy preset: `strict` \| `standard` \| `permissive` |
| `--redact-secrets` | `true` | Mask API keys, tokens, and database passwords in results |
| `--entropy-scan` | `true` | Flag high-entropy tokens matching no known pattern (audit-only unless `--entropy-mask`) |
| `--entropy-mask` | `false` | Mask entropy findings instead of just auditing them (noisier: hashes, base64, signed URLs) |
| `--scan-injection` | `true` | Strip hidden Unicode & neutralize prompt-injection directives |
| `--neutralize-injection` | `true` | Rewrite detected directives (off = detect + log only) |
| `--scan-requests` | `true` | Warn when outbound tool-call arguments contain secrets |
| `--block-shell` | `true` | Block execution of shell scripts in exec-like tools |
| `--block-sensitive-reads` | `false` | Block reads of protected paths (default: allow + redact) |
| `--rate-limit N` | `0` | Max tool calls/min before throttling (0 = disabled) |
| `--annotate-tools` | `true` | Append policy notices to `tools/list` so agents know boundaries |
| `--compress` | `false` | Strip comments and blank lines from context (safe tools only) |
| `--max-tokens N` | `0` | Approximate token budget cap per result block (0 = unlimited) |
| `--protect-paths` | *(defaults)* | Comma-separated protected paths (overrides defaults) |
| `--protect-names` | *(defaults)* | Comma-separated protected path segments (overrides defaults) |
| `--allow-shell` | *(none)* | Comma-separated allow-list substrings for shell commands |
| `--stats` | `true` | Print a session summary on exit and on `SIGUSR1` |
| `--price-per-1k` | `0.003` | USD per 1K tokens for the cost-saved estimate |
| `--log-level` | `info` | Verbosity: `silent` \| `error` \| `info` \| `debug` (**stderr**) |
| `--log-format` | `text` | Log format: `text` \| `json` (JSON Lines) |
| `--dry-run` | `false` | Log events without mutating the stream |
| `--http-listen` | *(none)* | Run as an HTTP/SSE proxy on this address (e.g. `:8080`) |
| `--http-upstream` | *(none)* | Upstream MCP server URL for HTTP/SSE mode |
| `--config` | *(none)* | Path to a JSON config file (optional) |

Signals: **`SIGHUP`** reloads config live · **`SIGUSR1`** prints an interim session summary.

---

## 🧪 Testing & Verification

```bash
# Run unit and integration tests
go test ./... -v

# Run static analysis
go vet ./...
```

Try it end-to-end against a real server:

```bash
printf '%s\n%s\n' \
'{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}' \
'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/path/to/a/.env"}}}' \
| mcp-guard --profile strict -- npx -y @modelcontextprotocol/server-filesystem /path/to
```

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
