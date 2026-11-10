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
		// ASCII only: a non-ASCII letter glued before (`é--token x`) does not hide a flag.
		if i > 0 && (s[i-1] == '-' || lex.IsNameChar(s[i-1])) {
			continue
		}
		// A single dash at a line's start is a removed diff row's marker.
		j := i + 1
		if j < len(s) && s[j] == '-' {
			j++
		} else if i == 0 || s[i-1] == '\n' {
			continue
		}
		// More dashes (`---passwd x`): only a password-family name after them is a flag, as a
		// receiver reads `--passwd` inside it; `---DSN start---` is a separator.
		extra := false
		for j < len(s) && s[j] == '-' {
			j++
			extra = true
		}
		ne := lex.NameRunAfter(s, j)
		if ne == j || !(lex.IsAlnumASCII(s[j]) || s[j] == '_') || !vocab.IsCredentialName(s[j:ne]) || (extra && !detect.FixedFlag(s[j:ne])) {
			continue
		}
		// Blanks and continuations, but not one into a diff's `-` or `+` row.
		v := ne
		for v < len(s) {
			if s[v] == ' ' || s[v] == '\t' {
				v++
				continue
			}
			// Percent-decoded, a diff row's `+` reads as a space: no continuation there.
			if n := lex.ContAt(s, v); n > 0 && !a.pct && !(v+n < len(s) && (s[v+n] == '+' || s[v+n] == '-')) {
				v += n
				continue
			}
			break
		}
		if v == ne || (v < len(s) && lex.ContAt(s, v) > 0) {
			continue
		}
		if lo, hi, ok := detect.HeredocAt(s, lex.SkipBlanks(s, ne)); ok {
			if !a.pct && hi > lo && live(heredocFirstLine(s, lo)) {
				a.hit("secret:flag-value")
			}
			continue
		}
		if strings.HasPrefix(s[v:], "<<<") {
			v = lex.SkipBlanks(s, v+3)
		}
		if v >= len(s) || (!detect.NotAnOption(s, v) && !(j == i+2 && s[v] != '\\' && (detect.FixedFlag(s[j:ne]) || (detect.AlwaysValued(s[j:ne]) && !detect.OptionLike(s, v))))) {
			continue
		}
		lo, hi := schemeValue(s, v)
		if live(s[lo:hi]) {
			a.hitAt("secret:flag-value", lo, hi)
		}
	}
}

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
				if !strings.HasPrefix(s[at:], po.Option) {
					continue
				}
				k := at + len(po.Option)
				v := lex.SkipBlanksConts(s, k)
				if !po.Attached && v == k {
					continue
				}
				if v < len(s) && detect.NotAnOption(s, v) {
					lo, hi := lex.CrudeValue(s, v)
					if live(s[lo:hi]) {
						a.hitAt("secret:flag-value", lo, hi)
					}
				}
			}
		}
	}
	// curl's user:password: whatever follows the user's colon in its argument.
	for _, p := range detect.Programs(s, "curl") {
		for _, at := range detect.CommandArgs(s, p, "curl") {
			if s[at] != '-' {
				continue
			}
			isUser := optionWord(s, at, "--user") || optionWord(s, at, "--proxy-user") ||
				(len(s) > at+1 && (s[at+1] == 'U' || strings.Contains(strings.SplitN(s[at:], " ", 2)[0], "u")) && !strings.HasPrefix(s[at:], "--"))
			if !isUser {
				continue
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
				// Short options combine (`-kuadmin:x`): the user is what follows the `u`/`U` in the same word.
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
			}
			if v >= len(s) {
				continue
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
	}
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
