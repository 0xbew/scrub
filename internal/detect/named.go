package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// --- R1: named values --------------------------------------------------------------------

// named: `NAME=value`, a quoted `"NAME"=value`, every `=` read on its own.
func (c *Scan) named() {
	s := c.S
	outerEnd, depth := 0, 0
	for p := strings.IndexByte(s, '='); p >= 0; p = lex.NextByte(s, '=', p+1) {
		vs := p + 1
		q := lex.NameRunBefore(s, p)
		var name string
		if q < p {
			name = lex.TrimDashes(s[q:p])
		} else if p > 0 && (s[p-1] == ' ' || s[p-1] == '\t') {
			c.spacedKeywordAssignment(p)
			continue
		} else if p > 0 && (s[p-1] == '"' || s[p-1] == '\'') {
			// A quoted name before `=`: `"DB_PASSWORD"=x`, `\"token\"=x`.
			e := p - 1
			for e > 0 && s[e-1] == '\\' {
				e--
			}
			q2 := lex.NameRunBefore(s, e)
			if q2 == e || q2 == 0 || s[q2-1] != s[p-1] {
				continue
			}
			name = lex.TrimDashes(s[q2:e])
			if !vocab.IsCredentialName(name) {
				continue
			}
			ve := lex.ValueEnd(s, vs)
			c.hideValue(vs, ve)
			continue
		} else {
			continue
		}
		if name == "" || !(lex.IsAlnumASCII(name[0]) || name[0] == '_') {
			continue
		}
		ve := lex.ValueEnd(s, vs)
		if ve == vs {
			c.nextLineValue(name, vs)
			continue
		}
		if HasKeyword(name) {
			// Assignments nested in one value are followed this deep; past it the value goes.
			if q < outerEnd {
				depth++
			} else {
				depth = 0
			}
			if ve > outerEnd {
				outerEnd = ve
			}
		}
		if judged(name, s[vs:ve]) || (c.R.Pctd && judged(name, c.sourceText(vs, ve))) || depth >= maxNestedAssignments {
			c.hideValue(vs, ve)
			if c.R.Pctd {
				c.extendEncoded(vs, ve)
			}
		}
	}
}

// nextLineValue: a credential's empty assignment ending its line (`TOKEN=`) and a quoted string opening the next
// one: a receiver may read the string as the value, so its body goes.
func (c *Scan) nextLineValue(name string, vs int) {
	s := c.S
	if !vocab.IsCredentialName(name) {
		return
	}
	j := vs
	if j < len(s) && s[j] == '\r' {
		j++
	}
	if j >= len(s) || s[j] != '\n' {
		return
	}
	j = lex.SkipBlanks(s, j+1)
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		c.hideQuotedBody(j, lex.ValueEnd(s, j))
	}
}

// spacedKeywordAssignment: `name = value` with blanks around the `=`, for a keyword name that is not a
// credential's (a credential's is the code detector's), whose value looks random (`airtable_key = k6hn7qed88vb`).
func (c *Scan) spacedKeywordAssignment(p int) {
	s := c.S
	if p+1 >= len(s) || (s[p+1] != ' ' && s[p+1] != '\t') {
		return
	}
	e := p
	for e > 0 && (s[e-1] == ' ' || s[e-1] == '\t') {
		e--
	}
	q := lex.NameRunBefore(s, e)
	if q == e || (q > 0 && strings.IndexByte("=!<>", s[q-1]) >= 0) {
		return
	}
	name := lex.TrimDashes(s[q:e])
	if name == "" || vocab.IsCredentialName(name) || !HasKeyword(name) {
		return
	}
	v := lex.SkipBlanks(s, p+1)
	ve := v
	for ve < len(s) && (lex.IsAlnumASCII(s[ve]) || strings.IndexByte("-_+/=.~", s[ve]) >= 0) {
		ve++
	}
	for ve > v && strings.IndexByte(".,;:!?)]}", s[ve-1]) >= 0 {
		ve--
	}
	// The word must end there: a quote or a bracket glued on makes it code.
	if ve < len(s) && !lex.IsSpaceByte(s[ve]) && strings.IndexByte(".,;:!?)]}\"'`", s[ve]) < 0 {
		return
	}
	if ve > v && judged(name, s[v:ve]) {
		c.hideValue(v, ve)
	}
}

// maxNestedAssignments: `key=key=...` is read this deep before its value is redacted.
const maxNestedAssignments = 20
