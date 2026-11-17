package label

import (
	"regexp"
	"strings"
)

// HiddenText reports text in tool output that a person reading it would
// not see, and returns its kind ("" when there is none). Prompt injections
// hide in these places, so the user cannot spot the instruction the agent
// reads:
//   - unicode_tags: Unicode tag characters (U+E0000–U+E007F), which encode
//     ASCII invisibly. Flag emoji use them after U+1F3F4; those are skipped.
//   - bidi_override: bidirectional overrides and isolates, which make text
//     display in a different order than the agent reads it.
//   - zero_width: a run of 4 or more zero-width characters, the usual way
//     to encode a hidden message. Single ones join emoji and words.
//   - html_comment, hidden_html: an HTML comment, or an element styled to
//     be invisible, that holds an instruction to an AI or a request for
//     secrets.
func HiddenText(text string) string {
	tags, run := 0, 0
	inFlag := false
	for _, r := range text {
		switch {
		case r == 0x1F3F4:
			inFlag = true
		case r >= 0xE0000 && r <= 0xE007F:
			if !inFlag {
				tags++
			}
			if r == 0xE007F {
				inFlag = false
			}
		default:
			inFlag = false
		}
		switch r {
		case 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069:
			return "bidi_override"
		case 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF:
			if run++; run >= 4 {
				return "zero_width"
			}
		default:
			run = 0
		}
	}
	if tags > 0 {
		return "unicode_tags"
	}
	for _, m := range htmlComment.FindAllStringSubmatch(text, 50) {
		if injection.MatchString(m[1]) {
			return "html_comment"
		}
	}
	for _, m := range invisibleHTML.FindAllStringSubmatch(text, 50) {
		if injection.MatchString(m[1]) {
			return "hidden_html"
		}
	}
	return ""
}

// HiddenKindText describes a HiddenText kind for the user.
func HiddenKindText(kind string) string {
	return map[string]string{
		"unicode_tags":  "invisible Unicode tag characters",
		"bidi_override": "Unicode characters that reorder the displayed text",
		"zero_width":    "a run of zero-width characters",
		"html_comment":  "an HTML comment with instructions",
		"hidden_html":   "HTML styled to be invisible, with instructions",
	}[strings.TrimPrefix(kind, "hidden_text:")]
}

var (
	htmlComment   = regexp.MustCompile(`(?s)<!--(.{0,1000}?)-->`)
	invisibleHTML = regexp.MustCompile(`(?is)<[a-z][^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^>]*>([^<]{0,1000})`)
	// injection: wording aimed at an AI agent, or a request to move secrets.
	injection = regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget)\b.{0,30}\b(?:previous|prior|above|earlier|all)\b.{0,20}\b(?:instructions?|rules|prompts?)\b` +
		`|\b(?:ai|llm|assistant|agent|claude|copilot|gpt|gemini)\b.{0,40}\b(?:must|should|need to|please|always)\b` +
		`|\bsystem prompt\b|\bnew instructions\b|<\|im_start\|>` +
		`|\bwithout (?:telling|asking|informing|notifying) the user\b|\bdo not (?:tell|inform|mention|show)\b.{0,20}\buser\b` +
		`|\b(?:send|upload|post|email|exfiltrate|copy)\b.{0,60}(?:\.env\b|\bsecrets?\b|\btokens?\b|\bpasswords?\b|\bcredentials?\b|\bprivate keys?\b|\bid_rsa\b)`)
)
