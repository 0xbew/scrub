package audit

import (
	"strings"

	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// code: a credential's name assigned in source: the first literal of the statement that
// still holds text, or a bare value that is not code.
func (a *auditor) code() {
	s := a.s
	for i := 0; i < len(s); i++ {
		if !lex.IsNameChar(s[i]) || (i > 0 && lex.IsNameChar(s[i-1])) {
			continue
		}
		e := lex.NameRunAfter(s, i)
		for i < e && s[i] == '-' {
			i++
		}
		if i == e {
			i = e - 1
			continue
		}
		name := s[i:e]
		if !vocab.IsCredentialName(name) {
			i = e - 1
			continue
		}
		var v int
		if i >= 4 && strings.EqualFold(s[i-4:i], "var ") {
			v = detect.CodeOpAfter(s, e, true)
		} else {
			v = detect.CodeOpAfter(s, e, false)
		}
		if v < 0 {
			// `getenv("NAME", "x")`
			if i > 0 && (s[i-1] == '"' || s[i-1] == '\'') && e < len(s) && (s[e] == '"' || s[e] == '\'') {
				k := lex.SkipBlanks(s, e+1)
				if k < len(s) && s[k] == ',' && a.literalLive(lex.SkipBlanks(s, k+1), lex.LineEnd(s, k)) {
					a.hit("secret:named-value")
				}
			}
			i = e - 1
			continue
		}
		if lo, hi, ok := detect.HeredocAt(s, v); ok {
			if hi > lo && live(heredocFirstLine(s, lo)) {
				a.hit("secret:named-value")
			}
			i = e - 1
			continue
		}
		w := detect.OpenersEnd(s, v)
		if w < len(s) && s[w] == '[' {
			if arrayLive(s, w) {
				a.hitAt("secret:named-value", w+1, arrayBodyEnd(s, w))
			}
		} else if !detect.IsCodeValue(s, w) && !detect.StartsLiteral(s, w) && !detect.StartsPlaceholder(s, w) {
			if we := detect.CodeWordEnd(s, w); we > w && live(s[w:we]) {
				a.hitAt("secret:named-value", w, we)
			}
		}
		end := lex.LineEnd(s, w)
		if w == end && end < len(s) {
			// a bracket or `=` at the line's end: the literal on a later line
			end = detect.StatementEnd(s, w)
		}
		if a.literalLive(w, end) {
			a.hit("secret:named-value")
		}
		i = e - 1
	}
	a.sqlAndEnv()
}

// literalLive: a literal in s[i:end] (up to 400 characters on) that holds text other than
// a placeholder.
func (a *auditor) literalLive(i, end int) bool {
	s := a.s
	if end > i+4000 {
		end = i + 4000
	}
	for i < end {
		_, open, slashes, quote, ok := detect.LiteralOpen(s, i, end)
		if !ok {
			return false
		}
		cl, closing := detect.LiteralEnd(s, open, slashes, quote, end)
		if closing != "" {
			body := s[open : cl-len(closing)]
			if live(body) {
				return true
			}
		}
		if cl <= open {
			cl = open + 1
		}
		i = cl
	}
	return false
}

func (a *auditor) sqlAndEnv() {
	s := a.s
	for _, m := range detect.SqlKeyRx.FindAllStringIndex(s, -1) {
		v := m[1]
		if v < len(s) && strings.IndexByte("EeNn", s[v]) >= 0 && v+1 < len(s) && s[v+1] == '\'' {
			v++
		}
		if v < len(s) && (s[v] == '\'' || s[v] == '"') {
			lo, hi := lex.CrudeValue(s, v)
			if live(s[lo:hi]) {
				a.hit("secret:named-value")
			}
		} else if strings.HasPrefix(s[v:], "$$") {
			k := strings.Index(s[v+2:lex.LineEnd(s, v)], "$$")
			if k > 0 && live(s[v+2:v+2+k]) {
				a.hit("secret:named-value")
			}
		}
	}
	for _, m := range detect.IdentifiedByRx.FindAllStringIndex(s, -1) {
		v := m[1]
		up := strings.ToUpper(s[v:])
		if strings.HasPrefix(up, "VALUES") || strings.HasPrefix(up, "PASSWORD") {
			continue
		}
		e := v
		for e < len(s) && !lex.IsSpaceByte(s[e]) && strings.IndexByte(";'\"$", s[e]) < 0 {
			e++
		}
		if live(s[v:e]) {
			a.hit("secret:named-value")
		}
	}
	for _, m := range detect.EnvRx.FindAllStringSubmatchIndex(s, -1) {
		if !vocab.IsCredentialName(s[m[2]:m[3]]) {
			continue
		}
		v := m[1]
		if v < len(s) && s[v] != '=' && live(s[v:lex.LineEnd(s, v)]) {
			a.hit("secret:named-value")
		}
	}
}
