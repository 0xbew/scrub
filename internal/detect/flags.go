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
		i = c.flagAt(i)
	}
}

// flagAt: the dash at i, when it starts a credential's flag: its value hidden. The index the
// next dash is searched after: i, or, after more than two dashes, two before the name.
func (c *Scan) flagAt(i int) int {
	s := c.S
	// ASCII only: a non-ASCII letter glued before (`é--token x`) does not hide a flag.
	if i > 0 && (s[i-1] == '-' || lex.IsNameChar(s[i-1])) {
		return i
	}
	j, extra := flagDashesEnd(s, i)
	if j >= len(s) || !nameStartByte(s[j]) {
		return i
	}
	ne := lex.NameRunAfter(s, j)
	name := s[j:ne]
	if !vocab.IsCredentialName(name) || (extra && !FixedFlag(name)) {
		return i
	}
	if extra {
		i = j - 2 // read as the double-dash flag it ends with
	}
	c.flagValue(i, j, ne, name)
	return i
}

// flagDashesEnd: past the one or two dashes of a flag at i and any more after them (extra).
func flagDashesEnd(s string, i int) (j int, extra bool) {
	j = i + 1
	if j < len(s) && s[j] == '-' {
		j++
	}
	// More dashes (`---passwd x`): a password-family name after them is still `--passwd`.
	extra = false
	for j < len(s) && s[j] == '-' {
		j++
		extra = true
	}
	return j, extra
}

// nameStartByte: a flag's or an assignment's name may start with c: an ASCII letter, digit or `_`.
func nameStartByte(c byte) bool { return lex.IsAlnumASCII(c) || c == '_' }

// flagValue: the value of the flag name s[j:ne] whose dashes start at i, past blanks or a
// continuation: a heredoc, a here-string's word, an escaped heredoc or a word.
func (c *Scan) flagValue(i, j, ne int, name string) {
	s := c.S
	k := ne
	sep := lex.SkipBlanksConts(s, k)
	if sep == k {
		return
	}
	if lo, hi, ok := HeredocAt(s, lex.SkipBlanks(s, k)); ok {
		c.hideValue(lo, hi)
		// A password-family flag's value is also the word at the opener, as a receiver reading
		// `--token VALUE` takes it.
		if w := lex.SkipBlanks(s, k); j == i+2 && FixedFlag(name) {
			c.hideValue(w, lex.ValueEnd(s, w))
		}
		return
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
	if v >= len(s) || (!NotAnOption(s, v) && !longFlagTakes(s, i, j, v, name)) {
		return
	}
	if e := escapedHeredocEnd(s, v); e > v {
		c.hideValue(v, e)
		return
	}
	c.hideValue(v, lex.ValueEnd(s, v))
}

// longFlagTakes: the flag name, long (two dashes from i to j), takes the word at v even when
// it reads as an option: a fixed flag, or one always valued whose word is not option-like.
func longFlagTakes(s string, i, j, v int, name string) bool {
	return j == i+2 && (FixedFlag(name) || (AlwaysValued(name) && !OptionLike(s, v)))
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
