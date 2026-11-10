package detect

import (
	"regexp"
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// --- .netrc ------------------------------------------------------------------------------

// netrcHead: where a .netrc entry may open: `machine` or `default` as a word of its own.
var netrcHead = regexp.MustCompile(`(?:^|[^\w.])(machine|default)[ \t]`)

// netrcWord: one .netrc token at i, after blanks and line breaks: a quoted string (raw or escaped) to its
// closing quote, else a run to a blank, a quote or a written escape (`\n` in a printf); an escaped space goes on.
// Returns the token's span, its body's span (inside quotes), or ok false at the end of the text.
func netrcWord(s string, i int) (lo, hi, blo, bhi int, ok bool) {
	for i < len(s) && lex.IsSpaceByte(s[i]) {
		i++
	}
	if i >= len(s) {
		return 0, 0, 0, 0, false
	}
	for _, q := range []string{`\"`, `"`, `'`} {
		if strings.HasPrefix(s[i:], q) {
			if k := strings.Index(s[i+len(q):], q); k >= 0 {
				e := i + len(q) + k
				return i, e + len(q), i + len(q), e, true
			}
		}
	}
	j := i
	for j < len(s) {
		ch := s[j]
		if ch == '\\' && j+1 < len(s) && s[j+1] == ' ' {
			j += 2
			continue
		}
		if lex.IsSpaceByte(ch) || ch == '"' || ch == '\'' || ch == '`' || (ch == '\\' && j+1 < len(s) && lex.IsAlnumASCII(s[j+1])) {
			break
		}
		j++
	}
	return i, j, i, j, j > i
}

// netrc: the passwords of a .netrc entry, on one line or several (`machine host login user password VALUE`). An
// entry is one with a dotted host or localhost, or a login before the password, so prose about a machine or a
// default password is not one.
func (c *Scan) netrc() {
	s := c.S
	if !strings.Contains(s, "password") {
		return
	}
	for _, m := range netrcHead.FindAllStringSubmatchIndex(s, -1) {
		i := m[3]
		entry := false
		if s[m[2]:m[3]] == "machine" {
			lo, hi, _, _, ok := netrcWord(s, i)
			if !ok {
				continue
			}
			host := s[lo:hi]
			entry = strings.Contains(host, ".") || host == "localhost"
			i = hi
		}
		for {
			lo, hi, _, _, ok := netrcWord(s, i)
			if !ok {
				break
			}
			key := s[lo:hi]
			if key != "login" && key != "account" && key != "port" && key != "password" {
				break
			}
			_, vhi, blo, bhi, ok := netrcWord(s, hi)
			if !ok {
				break
			}
			if key == "login" {
				entry = true
			}
			if key == "password" && entry && bhi > blo {
				c.hideValue(blo, bhi)
			}
			i = vhi
		}
	}
}
