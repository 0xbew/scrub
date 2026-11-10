package auditnet

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0xbew/scrub/internal/denylist"
	"github.com/0xbew/scrub/internal/lex"
)

// --- addresses and phone numbers ---------------------------------------------------------------------------

var netEmailRx = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

// netEmail: an address whose last label is two or more letters standing as a word's end.
func netEmail(s string) bool {
	for _, m := range netEmailRx.FindAllStringIndex(s, -1) {
		if m[1] >= len(s) || !(lex.IsAlnumASCII(s[m[1]]) || s[m[1]] == '-') {
			return true
		}
	}
	return false
}

var (
	netNANPRx = regexp.MustCompile(`(?:\+?1[ .-]?)?(?:\(\d{3}\) ?|\d{3}[ .-])\d{3}[ .-]\d{4}`)
	netIntlRx = regexp.MustCompile(`\+[1-9]\d{0,2}(?:[ .-]?\d{2,6}){1,5}`)
	// A date after a diff row's `+` (`+2026-10-25 14`) is no number.
	netDateRx = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
)

// netPhone: a North American number in its written forms, or `+` and a country code with groups of digits
// (8 to 15 digits, no date), standing apart from words, `.`, `+` and `-` on either side.
func netPhone(s string) bool {
	texts := []string{s}
	// A diff document's rows are read without their marker, as the scrubber reads a diff's sides; a diff quoted
	// inside other text (a test's string) is read as written, where `+(415) …` is a marker and a row, no number.
	if strings.HasPrefix(s, "diff --git ") || strings.HasPrefix(s, "--- ") || strings.HasPrefix(s, "@@ -") {
		var b strings.Builder
		for _, ln := range strings.SplitAfter(s, "\n") {
			if ln != "" && strings.IndexByte("+- ", ln[0]) >= 0 {
				ln = ln[1:]
			}
			b.WriteString(ln)
		}
		texts = append(texts, b.String())
	}
	for _, t := range texts {
		for _, m := range netNANPRx.FindAllStringIndex(t, -1) {
			if netPhoneApart(t, m[0], m[1]) {
				return true
			}
		}
		for _, m := range netIntlRx.FindAllStringIndex(t, -1) {
			digits := 0
			for i := m[0]; i < m[1]; i++ {
				if lex.IsDigitASCII(t[i]) {
					digits++
				}
			}
			if digits >= 8 && digits <= 15 && netPhoneApart(t, m[0], m[1]) && !netDateRx.MatchString(t[m[0]:m[1]]) {
				return true
			}
		}
	}
	return false
}

func netPhoneApart(s string, lo, hi int) bool {
	if lo > 0 {
		if c := s[lo-1]; lex.IsAlnumASCII(c) || c == '_' || c == '.' || c == '+' || c == '-' {
			return false
		}
	}
	return hi >= len(s) || !(lex.IsAlnumASCII(s[hi]) || s[hi] == '_' || s[hi] == '-')
}

// --- the denylist's identities ------------------------------------------------------------------------------

// netIdentity: the identity's pattern anywhere in s; a literal one with no letter or digit, in any script, on
// either side.
func netIdentity(id denylist.Identity, s string) bool {
	for at := 0; at < len(s); {
		m := id.Rx.FindStringIndex(s[at:])
		if m == nil {
			return false
		}
		lo, hi := at+m[0], at+m[1]
		if hi > lo && (!id.Literal || !netAlnumRune(s, lo, true) && !netAlnumRune(s, hi, false)) {
			return true
		}
		// Glued to a letter or digit: a later match, or a shorter one a rune on, may stand.
		_, sz := utf8.DecodeRuneInString(s[lo:])
		if sz == 0 {
			sz = 1
		}
		at = lo + sz
	}
	return false
}

func netAlnumRune(s string, i int, before bool) bool {
	var r rune
	if before {
		if i <= 0 {
			return false
		}
		r, _ = utf8.DecodeLastRuneInString(s[:i])
	} else {
		if i >= len(s) {
			return false
		}
		r, _ = utf8.DecodeRuneInString(s[i:])
	}
	return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.Is(unicode.Mn, r)
}
