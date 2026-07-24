// Package guard enforces mcp-guard's directory and shell policies against
// outbound tools/call requests, and annotates tools/list results so the agent
// knows the policy up front.
package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/sainitish1609/mcp-guard/internal/config"
)

// AnnotationMarker identifies mcp-guard's tools/list notice so annotation is
// idempotent across re-proxying.
const AnnotationMarker = "[Protected by mcp-guard"

// mutatingVerbs are tool-name substrings implying a write/modify operation.
var mutatingVerbs = []string{"write", "edit", "create", "delete", "remove", "move", "rename", "put", "append", "patch", "save", "mkdir", "copy"}

// readVerbs are tool-name substrings implying a read/fetch operation. Used only
// when BlockSensitiveReads is enabled to hard-block reads of protected paths
// (by default such reads are allowed and their contents are redacted instead).
var readVerbs = []string{"read", "get", "cat", "open", "view", "fetch", "load", "show"}

// Guard holds resolved policy state.
type Guard struct {
	cfg  config.Config
	home string
}

// New builds a Guard. cfg.ProtectPaths must already be expanded.
func New(cfg config.Config) *Guard {
	home, _ := os.UserHomeDir()
	return &Guard{cfg: cfg, home: home}
}

// Inspect decides whether a tools/call with the given name and arguments should
// be blocked. When blocked, reason is a human-readable explanation suitable for
// the isError result fed back to the agent.
func (g *Guard) Inspect(toolName string, args map[string]json.RawMessage) (blocked bool, reason string) {
	lname := strings.ToLower(toolName)

	if g.cfg.BlockShell && g.isShellTool(lname) {
		if cmd, bad := g.shellViolation(args); bad {
			return true, "shell script execution is restricted by mcp-guard security policy: " + cmd
		}
	}

	if g.isMutating(lname) {
		for _, val := range stringArgs(args) {
			if hit, ok := g.protectedPath(val); ok {
				return true, "write to '" + val + "' is restricted by mcp-guard security policy (protected path: " + hit + ")"
			}
		}
	}

	if g.cfg.BlockSensitiveReads && g.isReading(lname) {
		for _, val := range stringArgs(args) {
			if hit, ok := g.protectedPath(val); ok {
				return true, "read of '" + val + "' is restricted by mcp-guard security policy (protected path: " + hit + ")"
			}
		}
	}
	return false, ""
}

func (g *Guard) isMutating(lname string) bool {
	for _, v := range mutatingVerbs {
		if strings.Contains(lname, v) {
			return true
		}
	}
	return false
}

// IsRead reports whether the named tool is a read/fetch operation, for the
// anomaly detector's read-burst signal.
func (g *Guard) IsRead(toolName string) bool {
	return g.isReading(strings.ToLower(toolName))
}

func (g *Guard) isReading(lname string) bool {
	for _, v := range readVerbs {
		if strings.Contains(lname, v) {
			return true
		}
	}
	return false
}

func (g *Guard) isShellTool(lname string) bool {
	for _, t := range g.cfg.ShellTools {
		if strings.Contains(lname, strings.ToLower(t)) {
			return true
		}
	}
	return false
}

// shellViolation returns the offending command text if the arguments invoke a
// script or a pipe-to-shell pattern that isn't explicitly allow-listed.
func (g *Guard) shellViolation(args map[string]json.RawMessage) (string, bool) {
	for _, val := range stringArgs(args) {
		lower := strings.ToLower(val)
		if g.isAllowed(lower) {
			continue
		}
		if strings.HasSuffix(lower, ".sh") ||
			strings.HasSuffix(lower, ".ps1") ||
			strings.Contains(lower, "bash -c") ||
			strings.Contains(lower, "sh -c") ||
			strings.Contains(lower, "| sh") ||
			strings.Contains(lower, "| bash") ||
			strings.Contains(lower, "curl ") && strings.Contains(lower, "sh") ||
			strings.Contains(lower, "wget ") && strings.Contains(lower, "sh") {
			return val, true
		}
	}
	return "", false
}

func (g *Guard) isAllowed(lowerCmd string) bool {
	for _, a := range g.cfg.AllowShell {
		if a != "" && strings.Contains(lowerCmd, strings.ToLower(a)) {
			return true
		}
	}
	return false
}

// protectedPath reports whether target is protected. It expands ~, cleans the
// path (collapsing ../ traversal), then applies two checks:
//   - protected names: a sensitive segment (.ssh, .git, id_rsa, …) appearing
//     anywhere in the path — regardless of location;
//   - protected paths: absolute/location-specific prefixes (/etc, ~/.config/gh).
func (g *Guard) protectedPath(target string) (string, bool) {
	if target == "" {
		return "", false
	}
	clean := target
	if strings.HasPrefix(clean, "~") && g.home != "" {
		clean = filepath.Join(g.home, strings.TrimPrefix(clean, "~"))
	}
	clean = filepath.Clean(clean)

	var abs string
	if filepath.IsAbs(clean) {
		abs = clean
	} else if a, err := filepath.Abs(clean); err == nil {
		abs = a
	}

	// Resolve symlinks on the existing portion of the path so a benign-looking
	// link (e.g. project/data -> ~/.ssh) cannot smuggle a write past the guard.
	resolved := resolveExisting(abs)

	// Name-based guard: a sensitive segment anywhere in the path.
	for _, cand := range []string{clean, abs, resolved} {
		if cand == "" {
			continue
		}
		if hit, ok := matchesName(cand, g.cfg.ProtectNames); ok {
			return hit, true
		}
	}

	// Path-based guard: absolute prefixes and relative component fallbacks.
	for _, p := range g.cfg.ProtectPaths {
		if filepath.IsAbs(p) {
			if (abs != "" && underPath(abs, p)) || (resolved != "" && underPath(resolved, p)) {
				return p, true
			}
		} else {
			if hasComponent(clean, p) || (abs != "" && hasComponent(abs, p)) {
				return p, true
			}
		}
	}
	return "", false
}

// resolveExisting resolves symlinks over the deepest existing ancestor of p and
// re-appends the non-existent remainder. Returns p unchanged if nothing can be
// resolved. This lets the guard see through a symlinked directory even when the
// final target file does not exist yet (the common case for a write).
func resolveExisting(p string) string {
	if p == "" {
		return p
	}
	cur := p
	var tail []string
	for {
		if _, err := os.Lstat(cur); err == nil {
			real, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return p
			}
			parts := append([]string{real}, reverse(tail)...)
			return filepath.Join(parts...)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

// reverse returns a reversed copy of s.
func reverse(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

// matchesName reports the first protected name that appears as a path segment in
// p. A segment matches when it equals the name, or begins with "<name>." (so
// ".env" also covers ".env.local"). Names may be given with or without a leading
// separator.
func matchesName(p string, names []string) (string, bool) {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == "" {
			continue
		}
		for _, n := range names {
			n = strings.Trim(n, "/")
			if n == "" {
				continue
			}
			if seg == n || strings.HasPrefix(seg, n+".") {
				return n, true
			}
		}
	}
	return "", false
}

// underPath reports whether target is base or nested within base.
func underPath(target, base string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

// hasComponent reports whether name appears as a full path segment in p, or p
// ends with it (covers files like ".env").
func hasComponent(p, name string) bool {
	name = strings.Trim(name, string(filepath.Separator))
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == name {
			return true
		}
	}
	return false
}

// stringArgs extracts every string-valued argument (recursively through nested
// objects/arrays) so paths and commands buried in structured arguments are seen.
func stringArgs(args map[string]json.RawMessage) []string {
	var out []string
	for _, raw := range args {
		collectStrings(raw, &out)
	}
	return out
}

func collectStrings(raw json.RawMessage, out *[]string) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return
	}
	walkValue(v, out)
}

func walkValue(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case []any:
		for _, e := range t {
			walkValue(e, out)
		}
	case map[string]any:
		for _, e := range t {
			walkValue(e, out)
		}
	}
}

// Annotate returns a description with mcp-guard's policy notice appended. It is
// idempotent: an already-annotated description is returned unchanged.
func (g *Guard) Annotate(desc string) string {
	if strings.Contains(desc, AnnotationMarker) {
		return desc
	}
	notice := AnnotationMarker + ": restricted paths (~/.ssh, ~/.aws, .env, .git) and shell scripts are blocked]"
	if desc == "" {
		return notice
	}
	return desc + "\n\n" + notice
}
