package vocab

import (
	"regexp"
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/tokens"
)

// --- identifiers written as code --------------------------------------------------------

const (
	maxIdentWordChars     = 20
	maxIdentMixedChars    = 6
	maxIdentMixedParts    = 2
	maxIdentNumberChars   = 8
	maxIdentConsonantRun  = 4
	minIdentVowelShare    = 0.25
	minIdentLongestWord   = 5
	maxDefinitionIndent   = 64
	identifierMinRunChars = 32
)

var identMixedRx = regexp.MustCompile(`^(?:[a-z]+[0-9]+|[0-9]+[a-z]{1,4}|[a-z]{1,2}[0-9]{1,2}[a-z]{1,2})$`)

func isConsonant(c byte) bool {
	return lex.IsLowerASCII(c) && !strings.ContainsRune("aeiou", rune(c))
}

// IsIdentifier reports whether a long run is lowercase words joined by `_`
// (`test_a_401_stops_the_run_instead_of_marching_on`).
func IsIdentifier(run string) bool {
	if run == "" {
		return false
	}
	for i := 0; i < len(run); i++ {
		c := run[i]
		if !(lex.IsLowerASCII(c) || lex.IsDigitASCII(c) || c == '_') {
			return false
		}
	}
	var parts []string
	for _, p := range strings.Split(run, "_") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	trimmed := strings.TrimLeft(run, "_")
	if len(parts) == 0 {
		return false
	}
	for _, p := range tokens.IdentPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return false
		}
	}
	mixed := 0
	longest := false
	for _, part := range parts {
		var limit int
		switch {
		case isAlphaStr(part):
			limit = maxIdentWordChars
			if len(part) >= minIdentLongestWord {
				longest = true
			}
		case isDigitStr(part):
			limit = maxIdentNumberChars
		default:
			mixed++
			if identMixedRx.MatchString(part) {
				limit = maxIdentMixedChars
			}
		}
		if len(part) > limit {
			return false
		}
	}
	if mixed > maxIdentMixedParts || !longest {
		return false
	}
	runLen := 0
	letters, vowels := 0, 0
	for i := 0; i < len(run); i++ {
		c := run[i]
		// [b-df-hj-np-tv-xz]: y is neither a consonant here nor a break.
		if lex.IsLowerASCII(c) && c != 'y' && !strings.ContainsRune("aeiou", rune(c)) {
			runLen++
			if runLen > maxIdentConsonantRun {
				return false
			}
		} else {
			runLen = 0
		}
		if lex.IsLowerASCII(c) {
			letters++
			if strings.ContainsRune("aeiouy", rune(c)) {
				vowels++
			}
		}
	}
	return float64(vowels) >= minIdentVowelShare*float64(letters)
}

// WrittenAsCode: a run that is a test's name, a call, a dotted path's part after its
// package, a `::` node id's name, or a definition's name.
func WrittenAsCode(text string, start, end int) bool {
	if strings.HasPrefix(text[start:end], "test_") {
		return true
	}
	if end < len(text) && text[end] == '(' {
		return true
	}
	if start >= 2 {
		b := text[start-2 : start]
		if b == "::" || (b[1] == '.' && (lex.IsAlnumASCII(b[0]) || b[0] == '_')) {
			return true
		}
	}
	lo := start - maxDefinitionIndent
	if lo < 0 {
		lo = 0
	}
	line := strings.LastIndexByte(text[lo:start], '\n')
	if line >= 0 {
		line += lo + 1
	} else {
		line = 0
	}
	if line > 0 || start <= maxDefinitionIndent {
		return isDefinitionLead(text[line:start])
	}
	return false
}

// `[+ -]?[ \t]*(?:async[ \t]+)?(?:def|class)[ \t]+` as a whole.
func isDefinitionLead(s string) bool {
	if s != "" && (s[0] == '+' || s[0] == ' ' || s[0] == '-') {
		// The marker is optional; a leading space may also be indentation. Both readings.
		if isDefinitionBody(s[1:]) {
			return true
		}
	}
	return isDefinitionBody(s)
}

func isDefinitionBody(s string) bool {
	s = strings.TrimLeft(s, " \t")
	if strings.HasPrefix(s, "async") {
		rest := s[5:]
		if t := strings.TrimLeft(rest, " \t"); len(t) < len(rest) {
			s = t
		}
	}
	for _, kw := range []string{"def", "class"} {
		if strings.HasPrefix(s, kw) {
			rest := s[len(kw):]
			if rest != "" && strings.Trim(rest, " \t") == "" {
				return true
			}
		}
	}
	return false
}
