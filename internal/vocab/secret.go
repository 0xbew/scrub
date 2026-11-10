package vocab

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/0xbew/scrub/internal/lex"
)

// --- the value classifier -------------------------------------------------------------

const (
	minSecretChars    = 16
	maxMixedPartChars = 20
)

var (
	wordPartRx  = regexp.MustCompile(`^(?:\d+|\d+(?:[a-z]+|[A-Z]+|[a-z]*(?:[A-Z][a-z]{2,})+)|(?:[a-z]+|[A-Z]+|[a-z]*(?:[A-Z][a-z]{2,})+)(?:\d+(?:[a-z]{3,}|[A-Z]{3,}|(?:[A-Z][a-z]{2,})+)?)?)$`)
	shortPartRx = regexp.MustCompile(`^(?:[a-z0-9]*|[A-Z0-9]+|[A-Z][a-z]+)$`)
)

func isValueSep(r rune) bool { return strings.ContainsRune("-_./:@+=,;()[]{}\\", r) }

func IsPathSep(r rune) bool { return r == '/' || r == '_' }

func splitRuns(text string, sep func(rune) bool) []string {
	// re.split keeps empty strings at the ends and between nothing; a run of separators is one split.
	var parts []string
	start := 0
	inSep := false
	for i, r := range text {
		if sep(r) {
			if !inSep {
				parts = append(parts, text[start:i])
				inSep = true
			}
		} else if inSep {
			start = i
			inSep = false
		}
	}
	if inSep {
		parts = append(parts, "")
	} else {
		parts = append(parts, text[start:])
	}
	return parts
}

func isAlphaStr(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func isDigitStr(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func Wordlike(text string, sep func(rune) bool) bool {
	for _, part := range splitRuns(text, sep) {
		if lex.RuneLen(part) <= 3 {
			if !shortPartRx.MatchString(part) {
				return false
			}
			continue
		}
		if !wordPartRx.MatchString(part) {
			return false
		}
		if lex.RuneLen(part) > maxMixedPartChars && !isAlphaStr(part) {
			return false
		}
	}
	return true
}

func hasDigitAndAlpha(s string) bool {
	d, a := false, false
	for _, r := range s {
		if unicode.IsDigit(r) {
			d = true
		} else if unicode.IsLetter(r) {
			a = true
		}
	}
	return d && a
}

// LooksSecret reports whether a value with no name to vouch for it is random-looking text
// of 16 or more characters.
func LooksSecret(value string) bool {
	value = strings.Trim(value, "\"'")
	if lex.RuneLen(value) < minSecretChars || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return false
	}
	if !hasDigitAndAlpha(value) {
		return false
	}
	return strings.IndexFunc(value, isValueSep) < 0 || !Wordlike(value, isValueSep)
}

func keepUnlessSecret(name, value string) bool {
	return !IsCredentialName(name) && !LooksSecret(value)
}
