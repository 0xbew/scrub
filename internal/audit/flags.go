package audit

import (
	"strings"

	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// flags: a credential's flag before a space or a continuation, and its value.
func (a *auditor) flags() {
	s := a.s
	for i := strings.IndexByte(s, '-'); i >= 0; i = lex.NextByte(s, '-', i+1) {
		a.flagAt(i)
	}
}

// flagAt: the dash at i, when it starts a credential's flag whose value is live.
func (a *auditor) flagAt(i int) {
	s := a.s
	j, ne, ok := flagNameAt(s, i)
	if !ok {
		return
	}
	v := a.flagBlanksEnd(ne)
	if v == ne || (v < len(s) && lex.ContAt(s, v) > 0) {
		return
	}
	if lo, hi, ok := detect.HeredocAt(s, lex.SkipBlanks(s, ne)); ok {
		if !a.pct && hi > lo && live(heredocFirstLine(s, lo)) {
			a.hit("secret:flag-value")
		}
		return
	}
	if strings.HasPrefix(s[v:], "<<<") {
		v = lex.SkipBlanks(s, v+3)
	}
	if flagValueRefused(s, i, j, ne, v) {
		return
	}
	lo, hi := schemeValue(s, v)
	if live(s[lo:hi]) {
		a.hitAt("secret:flag-value", lo, hi)
	}
}

// flagNameAt: the credential's name s[j:ne] of a flag whose dashes start at i; ok false
// when no flag stands there.
func flagNameAt(s string, i int) (j, ne int, ok bool) {
	// ASCII only: a non-ASCII letter glued before (`é--token x`) does not hide a flag.
	if i > 0 && (s[i-1] == '-' || lex.IsNameChar(s[i-1])) {
		return 0, 0, false
	}
	// A single dash at a line's start is a removed diff row's marker.
	j = i + 1
	if j < len(s) && s[j] == '-' {
		j++
	} else if i == 0 || s[i-1] == '\n' {
		return 0, 0, false
	}
	// More dashes (`---passwd x`): only a password-family name after them is a flag, as a
	// receiver reads `--passwd` inside it; `---DSN start---` is a separator.
	extra := false
	for j < len(s) && s[j] == '-' {
		j++
		extra = true
	}
	ne = lex.NameRunAfter(s, j)
	if ne == j || !asciiWordByte(s[j]) || !vocab.IsCredentialName(s[j:ne]) || (extra && !detect.FixedFlag(s[j:ne])) {
		return 0, 0, false
	}
	return j, ne, true
}

// flagBlanksEnd: past the blanks and continuations after a flag's name ending at ne, but not
// one into a diff's `-` or `+` row.
func (a *auditor) flagBlanksEnd(ne int) int {
	s := a.s
	v := ne
	for v < len(s) {
		if s[v] == ' ' || s[v] == '\t' {
			v++
			continue
		}
		// Percent-decoded, a diff row's `+` reads as a space: no continuation there.
		if n := lex.ContAt(s, v); n > 0 && !a.pct && !diffRowMarkAt(s, v+n) {
			v += n
			continue
		}
		break
	}
	return v
}

// flagValueRefused: no value at v for the flag s[j:ne] whose dashes start at i: the text
// ends, or what stands there is an option and the flag is not one that always takes a value.
func flagValueRefused(s string, i, j, ne, v int) bool {
	return v >= len(s) || (!detect.NotAnOption(s, v) && !longFlagValued(s, i, j, ne, v))
}

// longFlagValued: the flag s[j:ne] is long (two dashes from i) and takes the value at v even
// when it reads as an option: the value does not start with `\`, and the flag is fixed or always valued with a
// value that is not option-like.
func longFlagValued(s string, i, j, ne, v int) bool {
	return j == i+2 && s[v] != '\\' && (detect.FixedFlag(s[j:ne]) || (detect.AlwaysValued(s[j:ne]) && !detect.OptionLike(s, v)))
}

// asciiWordByte: an ASCII letter, digit or `_`.
func asciiWordByte(c byte) bool { return lex.IsAlnumASCII(c) || c == '_' }

// diffRowMarkAt: a diff row's `+` or `-` marker stands at k.
func diffRowMarkAt(s string, k int) bool { return k < len(s) && (s[k] == '+' || s[k] == '-') }

func firstLine(s string, i int) string { return s[i:lex.LineEnd(s, i)] }

// heredocFirstLine: a heredoc body's first line, without a diff row's marker (`+x = <<EOF` then `+<redacted>`, or an
// opener on a context row then an empty `+` row): the marker is the diff's, not the body's.
func heredocFirstLine(s string, lo int) string {
	line := firstLine(s, lo)
	if line != "" && (line[0] == '+' || line[0] == '-') {
		return line[1:]
	}
	return line
}

// options: the programs whose option holds a password with no name to read.
func (a *auditor) options() {
	s := a.s
	for _, po := range detect.PasswordOptions {
		for _, p := range detect.Programs(s, po.Program) {
			for _, at := range detect.CommandArgs(s, p, po.Program) {
				a.passwordOptionAt(at, po.Option, po.Attached)
			}
		}
	}
	// curl's user:password: whatever follows the user's colon in its argument.
	for _, p := range detect.Programs(s, "curl") {
		for _, at := range detect.CommandArgs(s, p, "curl") {
			a.curlUserAt(at)
		}
	}
	a.opensslPasses()
	a.npmAuths()
}

// passwordOptionAt: the argument at at, when it is the option `option` and the value it
// takes is live. attached: the value
// may be glued to the option.
func (a *auditor) passwordOptionAt(at int, option string, attached bool) {
	s := a.s
	if !strings.HasPrefix(s[at:], option) {
		return
	}
	k := at + len(option)
	v := lex.SkipBlanksConts(s, k)
	if !attached && v == k {
		return
	}
	if v < len(s) && detect.NotAnOption(s, v) {
		lo, hi := lex.CrudeValue(s, v)
		if live(s[lo:hi]) {
			a.hitAt("secret:flag-value", lo, hi)
		}
	}
}

// curlUserAt: curl's argument at at, when it is a user option and its value holds a live password.
func (a *auditor) curlUserAt(at int) {
	s := a.s
	if s[at] != '-' {
		return
	}
	isUser := optionWord(s, at, "--user") || optionWord(s, at, "--proxy-user") ||
		(len(s) > at+1 && (s[at+1] == 'U' || strings.Contains(strings.SplitN(s[at:], " ", 2)[0], "u")) && !strings.HasPrefix(s[at:], "--"))
	if !isUser {
		return
	}
	ae := at
	for ae < len(s) && !lex.IsSpaceByte(s[ae]) && s[ae] != '=' {
		ae++
	}
	v := ae
	if v < len(s) && s[v] == '=' {
		v++
	} else {
		v = lex.SkipBlanksConts(s, ae)
	}
	if !strings.HasPrefix(s[at:], "--") {
		v = shortUserValue(s, at, ae, v)
	}
	if v >= len(s) {
		return
	}
	lo, hi := lex.CrudeValue(s, v)
	arg := s[lo:hi]
	if k := strings.IndexByte(arg, ':'); k >= 0 {
		// After the user's colon: one value, as the receiver splits the argument.
		w0, w1 := schemeValue(s, detect.SkipConts(s, lo+k+1))
		if live(s[w0:w1]) {
			a.hitAt("secret:flag-value", w0, w1)
		}
	}
}

// shortUserValue: short options combine (`-kuadmin:x`): the user is what follows the `u`/`U` in the same word
// at..ae; v when nothing does.
func shortUserValue(s string, at, ae, v int) int {
	for k := at + 1; k < ae; k++ {
		if s[k] == 'u' || s[k] == 'U' {
			if k+1 < ae {
				v = k + 1
			}
			break
		}
		if !lex.IsLowerASCII(s[k]) && !lex.IsUpperASCII(s[k]) {
			break
		}
	}
	return v
}

// opensslPasses: openssl's `pass:` password argument.
func (a *auditor) opensslPasses() {
	s := a.s
	for _, m := range detect.OpensslPassRx.FindAllStringIndex(s, -1) {
		v := m[1]
		if v < len(s) && s[v] == '=' {
			v++
		} else {
			v = lex.SkipBlanksConts(s, v)
		}
		if v < len(s) && (s[v] == '"' || s[v] == '\'') {
			v++
		}
		if strings.HasPrefix(strings.ToLower(s[v:]), "pass:") {
			lo, hi := lex.CrudeValue(s, detect.SkipConts(s, v+5))
			if live(s[lo:hi]) {
				a.hitAt("secret:flag-value", lo, hi)
			}
		}
	}
}

// npmAuths: the value after npm's auth option.
func (a *auditor) npmAuths() {
	s := a.s
	for _, m := range detect.NpmAuthRx.FindAllStringIndex(s, -1) {
		v := lex.SkipBlanksConts(s, m[1])
		if v > m[1] && v < len(s) && detect.NotAnOption(s, v) {
			lo, hi := lex.CrudeValue(s, v)
			if live(s[lo:hi]) {
				a.hitAt("secret:flag-value", lo, hi)
			}
		}
	}
}

// optionWord: the long option opt stands at i whole (`--user`, `--user=x`), not as the start of another
// (`--user-agent`).
func optionWord(s string, i int, opt string) bool {
	if !strings.HasPrefix(s[i:], opt) {
		return false
	}
	k := i + len(opt)
	return k >= len(s) || s[k] == '=' || lex.IsSpaceByte(s[k]) || s[k] == '\\' || s[k] == '"' || s[k] == '\''
}
