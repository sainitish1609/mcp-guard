package inject

import "regexp"

// directiveRE matches high-signal prompt-injection directives — imperative
// phrases that try to override the agent's instructions, hide activity from the
// user, or exfiltrate data. The patterns are deliberately specific (verb +
// object) to keep false positives on normal prose low; a document merely
// mentioning "prompt injection" is not matched, but "ignore all previous
// instructions" is.
var directiveRE = regexp.MustCompile(`(?i)` + join(
	`ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|context|directions?|rules?)`,
	`disregard\s+(?:all\s+|any\s+|everything\s+)?(?:the\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|rules?|context|prompt)`,
	`forget\s+(?:everything|all\s+(?:the\s+)?(?:previous|prior)|your\s+(?:instructions?|rules?|prompt|training))`,
	`(?:new|updated|revised|real|actual|true)\s+(?:instructions?|system\s+prompt|directives?)\s*[:\-]`,
	`you\s+are\s+now\s+(?:a\s+|an\s+|the\s+)?(?:[a-z]+\s+){0,3}(?:assistant|ai|model|dan|developer\s+mode|jailbroken)`,
	`(?:do\s+not|don't|never)\s+(?:tell|inform|warn|alert|notify|mention\s+to)\s+(?:the\s+)?user`,
	`override\s+(?:your|the|all)\s+(?:instructions?|guardrails?|safety|restrictions?|rules?)`,
	`reveal\s+(?:your|the)\s+(?:system\s+prompt|instructions?|initial\s+prompt|configuration)`,
	`(?:print|output|repeat|echo)\s+(?:your|the)\s+(?:system\s+prompt|instructions?)`,
) + ``)

// join wraps each alternative in a non-capturing group and ORs them.
func join(alts ...string) string {
	s := ""
	for i, a := range alts {
		if i > 0 {
			s += "|"
		}
		s += "(?:" + a + ")"
	}
	return "(?:" + s + ")"
}
