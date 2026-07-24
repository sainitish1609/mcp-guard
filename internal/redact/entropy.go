package redact

import (
	"math"
	"regexp"
)

// candidateRE isolates token-like runs that could be a generated credential:
// long strings of base64url/hex/identifier characters. '/' is deliberately
// excluded so filesystem paths (which are full of slashes) are not treated as
// one giant token; base64 secrets containing '/' simply split into segments that
// are still long enough to trip the length+entropy gates.
var candidateRE = regexp.MustCompile(`[A-Za-z0-9+=_\-]{20,}`)

// entropy tuning. A random API key is high-entropy and mixes character classes;
// English words, git SHAs (hex only), and UUIDs (hex only) are excluded by the
// class requirement so they are not masked.
const (
	entropyMinLen     = 20
	entropyThreshold  = 3.5 // Shannon bits per character
	entropyMinClasses = 3   // of {lower, upper, digit, symbol}
)

// scanEntropy masks token-like substrings whose Shannon entropy and character
// diversity look like a generated secret rather than natural text or an
// identifier. It runs after the named patterns, so anything already masked
// (which contains ':' and brackets outside the token charset) is untouched.
func scanEntropy(text string) (string, int) {
	count := 0
	out := candidateRE.ReplaceAllStringFunc(text, func(tok string) string {
		if looksLikeSecret(tok) {
			count++
			return mask("high-entropy")
		}
		return tok
	})
	return out, count
}

// looksLikeSecret applies the length, class-diversity, and entropy gates.
func looksLikeSecret(tok string) bool {
	if len(tok) < entropyMinLen {
		return false
	}
	if charClasses(tok) < entropyMinClasses {
		return false
	}
	return shannonEntropy(tok) >= entropyThreshold
}

// charClasses counts how many of {lowercase, uppercase, digit, symbol} appear.
func charClasses(s string) int {
	var lower, upper, digit, symbol bool
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, symbol} {
		if b {
			n++
		}
	}
	return n
}

// shannonEntropy returns the per-character Shannon entropy (in bits) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
