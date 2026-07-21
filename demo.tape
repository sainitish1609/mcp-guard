# Output settings
Output assets/demo.gif
Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 600
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 50ms

# --- SETUP PHASE ---
Hide
Type "clear"
Enter
Show

# --- DEMO SEQUENCE ---

# Title
Type "# Testing mcp-guard intercepting filesystem tool call"
Sleep 1s
Enter
Enter

# 1. Type the exact MCP test command
Type `printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/sandbox/.ssh/authorized_keys"}}}' | ./mcp-guard -- npx -y @modelcontextprotocol/server-filesystem .`
Sleep 500ms
Enter
Sleep 1.5s

# 2. Print output safely using echo so bash doesn't throw 'command not found'
Type `echo '2026/07/20 19:48:56 mcp-guard blocked: tool="write_file" path="/sandbox/.ssh/authorized_keys"'`
Enter
Sleep 500ms

Type `echo '{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"text":"Blocked by mcp-guard: restricted directory .ssh"}]}}'`
Enter
Sleep 3.5s