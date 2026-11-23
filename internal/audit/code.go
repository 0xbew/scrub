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
		a.codeNameAt(i, e)
		i = e - 1
	}
	a.sqlAndEnv()
}

// codeNameAt: the name run s[i:e], past its leading dashes, when it is a credential's name
// and what is assigned to it is live, or, with no assignment, it is a lookup's key with a
// live default.
func (a *auditor) codeNameAt(i, e int) {
	s := a.s
	for i < e && s[i] == '-' {
		i++
	}
	if i == e {
		return
	}
	name := s[i:e]
	if !vocab.IsCredentialName(name) {
		return
	}
	v := a.codeOpAfter(i, e)
	if v < 0 {
		a.getenvDefault(i, e)
		return
	}
	if lo, hi, ok := detect.HeredocAt(s, v); ok {
		if hi > lo && live(heredocFirstLine(s, lo)) {
			a.hit("secret:named-value")
		}
		return
	}
	a.codeValueAt(v)
}

// codeOpAfter: where the value assigned to the name s[i:e] starts, -1 when no assignment
// follows; after `var `, a declaration's type may stand between.
func (a *auditor) codeOpAfter(i, e int) int {
	s := a.s
	var v int
	if i >= 4 && strings.EqualFold(s[i-4:i], "var ") {
		v = detect.CodeOpAfter(s, e, true)
	} else {
		v = detect.CodeOpAfter(s, e, false)
	}
	return v
}

// getenvDefault: the name s[i:e] quoted as a lookup's key with a live default after it
// (`getenv("NAME", "x")`).
func (a *auditor) getenvDefault(i, e int) {
	s := a.s
	if i > 0 && (s[i-1] == '"' || s[i-1] == '\'') && e < len(s) && (s[e] == '"' || s[e] == '\'') {
		k := lex.SkipBlanks(s, e+1)
		if k < len(s) && s[k] == ',' && a.literalLive(lex.SkipBlanks(s, k+1), lex.LineEnd(s, k)) {
			a.hit("secret:named-value")
		}
	}
}

// codeValueAt: the value assigned at v: an array of live items, a bare live value that is
// not code, and the first live literal of the statement.
func (a *auditor) codeValueAt(v int) {
	s := a.s
	w := detect.OpenersEnd(s, v)
	a.codeBareValue(w)
	end := lex.LineEnd(s, w)
	if w == end && end < len(s) {
		// a bracket or `=` at the line's end: the literal on a later line
		end = detect.StatementEnd(s, w)
	}
	if a.literalLive(w, end) {
		a.hit("secret:named-value")
	}
}

// codeBareValue: at w, an array whose items are live, or a bare value that is neither code,
// a literal nor a placeholder and is live.
func (a *auditor) codeBareValue(w int) {
	s := a.s
	if w < len(s) && s[w] == '[' {
		if arrayLive(s, w) {
			a.hitAt("secret:named-value", w+1, arrayBodyEnd(s, w))
		}
	} else if !detect.IsCodeValue(s, w) && !detect.StartsLiteral(s, w) && !detect.StartsPlaceholder(s, w) {
		if we := detect.CodeWordEnd(s, w); we > w && live(s[w:we]) {
			a.hitAt("secret:named-value", w, we)
		}
	}
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
		a.sqlKeyAt(m[1])
	}
	for _, m := range detect.IdentifiedByRx.FindAllStringIndex(s, -1) {
		a.identifiedByAt(m[1])
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

// sqlKeyAt: the value after a SQL key ending at v: a quoted string (`'...'`, `"..."`, `E'...'`,
// `N'...'`) or a dollar-quoted one on the same line, when live.
func (a *auditor) sqlKeyAt(v int) {
	s := a.s
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

// identifiedByAt: the bare word after an `IDENTIFIED BY` that ends at v, unless it is `VALUES`
// or `PASSWORD`, when live.
func (a *auditor) identifiedByAt(v int) {
	s := a.s
	up := strings.ToUpper(s[v:])
	if strings.HasPrefix(up, "VALUES") || strings.HasPrefix(up, "PASSWORD") {
		return
	}
	e := v
	for e < len(s) && !lex.IsSpaceByte(s[e]) && strings.IndexByte(";'\"$", s[e]) < 0 {
		e++
	}
	if live(s[v:e]) {
		a.hit("secret:named-value")
	}
}
