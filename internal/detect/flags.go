package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// --- flags --------------------------------------------------------------------------------

// NotAnOption: what is not an option's value: another option or `-`, or an operator.
func NotAnOption(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	if s[i] == '-' {
		if i+1 < len(s) && s[i+1] == '-' {
			return false
		}
		j := i + 1
		if j < len(s) && lex.IsAlnumASCII(s[j]) {
			j++
		}
		if j >= len(s) || lex.IsSpaceByte(s[j]) || s[j] == '"' || s[j] == '\'' {
			return false
		}
	}
	j := i
	if j < len(s) && s[j] == ':' {
		j++
	}
	if j < len(s) && s[j] == '=' && (j+1 >= len(s) || lex.IsSpaceByte(s[j+1])) {
		return false
	}
	return true
}

// flags: `--name value` and `-name value` for a credential's name, its heredoc, and the
// fixed `--password`-family flags.
func (c *Scan) flags() {
	s := c.S
	for i := strings.IndexByte(s, '-'); i >= 0; i = lex.NextByte(s, '-', i+1) {
		// ASCII only: a non-ASCII letter glued before (`é--token x`) does not hide a flag.
		if i > 0 && (s[i-1] == '-' || lex.IsNameChar(s[i-1])) {
			continue
		}
		j := i + 1
		if j < len(s) && s[j] == '-' {
			j++
		}
		// More dashes (`---passwd x`): a password-family name after them is still `--passwd`.
		extra := false
		for j < len(s) && s[j] == '-' {
			j++
			extra = true
		}
		if j >= len(s) || !(lex.IsAlnumASCII(s[j]) || s[j] == '_') {
			continue
		}
		ne := lex.NameRunAfter(s, j)
		name := s[j:ne]
		if !vocab.IsCredentialName(name) || (extra && !FixedFlag(name)) {
			continue
		}
		if extra {
			i = j - 2 // read as the double-dash flag it ends with
		}
		k := ne
		sep := lex.SkipBlanksConts(s, k)
		if sep == k {
			continue
		}
		if lo, hi, ok := HeredocAt(s, lex.SkipBlanks(s, k)); ok {
			c.hideValue(lo, hi)
			// A password-family flag's value is also the word at the opener, as a receiver reading
			// `--token VALUE` takes it.
			if w := lex.SkipBlanks(s, k); j == i+2 && FixedFlag(name) {
				c.hideValue(w, lex.ValueEnd(s, w))
			}
			continue
		}
		v := sep
		if strings.HasPrefix(s[v:], "<<<") {
			// A here-string: the value is the word after it. A password-family flag's value is also
			// the word at the operator, as a receiver reading `--token VALUE` takes it.
			if j == i+2 && FixedFlag(name) {
				c.hideValue(v, lex.ValueEnd(s, v))
			}
			v = lex.SkipBlanks(s, v+3)
		}
		if v >= len(s) || (!NotAnOption(s, v) && !(j == i+2 && (FixedFlag(name) || (AlwaysValued(name) && !OptionLike(s, v))))) {
			continue
		}
		if e := escapedHeredocEnd(s, v); e > v {
			c.hideValue(v, e)
			continue
		}
		c.hideValue(v, lex.ValueEnd(s, v))
	}
}

// fixedFlag: the password-family flags a receiver reads by name alone (`--token VALUE`).
// optionLike: the word at i reads as an option, not a value that starts with a dash: `-` (stdin), one letter
// (`-v`), or letters and dashes (`--verbose`, `-rf`). A password that starts with a dash holds more; so may
// what follows `=` in `--name=...`, which is taken as a value.
// A password-family flag (fixedFlag) takes even such a word, as a receiver reading `--token --x` does.
func OptionLike(s string, i int) bool {
	if i >= len(s) || s[i] != '-' {
		return false
	}
	j := i
	for j < len(s) && s[j] == '-' {
		j++
	}
	k := j
	for k < len(s) && (lex.IsLowerASCII(s[k]) || lex.IsUpperASCII(s[k]) || s[k] == '-') {
		k++
	}
	if k == j && j == i+1 && j < len(s) && lex.IsAlnumASCII(s[j]) {
		k++ // `-1`, `-9`: one character
	}
	return k >= len(s) || lex.IsSpaceByte(s[k]) || s[k] == '"' || s[k] == '\'' || s[k] == ';' || s[k] == '|' || s[k] == '&' || s[k] == ')'
}

func FixedFlag(name string) bool {
	switch strings.ToLower(name) {
	case "password", "passwd", "token", "apikey", "api-key", "api_key", "secret", "auth", "auth-token":
		return true
	}
	return false
}

// AlwaysValued: a double-dash flag whose next word is its value even when it looks like an
// option (`--password -Xy9`, `--token --verbose`): a password may start with a dash.
func AlwaysValued(name string) bool { return FixedFlag(name) || vocab.IsCredentialName(name) }
