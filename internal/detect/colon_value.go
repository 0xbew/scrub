package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/span"
	"github.com/0xbew/scrub/internal/vocab"
)

func (c *Scan) colonValue(name string, v int, flow, tight bool) {
	s := c.S
	if vocab.IsCredentialName(name) {
		end := colonWords(s, v, flow, tight)
		c.hideColonBody(v, end, true)
		return
	}
	var end int
	if tight {
		end = lex.ValueEndFlow(s, v)
	} else {
		end = lex.ValueEnd(s, v)
	}
	if end > v && judged(name, s[v:end]) {
		c.hideColonBody(v, end, false)
	}
}

// hideColonBody: the value proper, without the `,` `;` `}` `]` that close the literal; a
// quoted value that closes keeps its quotes, any other goes whole.
// With words, the value is every word to a stop word: a placeholder then more words is a
// value partly sent (`authorization: <redacted> <token_or_cookie>`), and it goes whole.
func (c *Scan) hideColonBody(a, b int, words bool) {
	for b > a && strings.IndexByte(",;}]", c.S[b-1]) >= 0 {
		b--
	}
	v := c.S[a:b]
	if len(v) > 1 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		c.hideValue(a+1, b-1)
		return
	}
	if words {
		c.hideWords(a, b)
		return
	}
	c.hideValue(a, b)
}

// quotedNameBeforeColon: `"name"` then whitespace or continuations (line breaks too) before p.
func (c *Scan) quotedNameBeforeColon(p int) (int, int, bool) {
	s := c.S
	e := p
	for e > 0 {
		if lex.IsSpaceByte(s[e-1]) {
			e--
			continue
		}
		if e >= 2 && s[e-1] == '\n' && s[e-2] == '\\' {
			e -= 2
			continue
		}
		break
	}
	if e == 0 || (s[e-1] != '"' && s[e-1] != '\'') {
		return 0, 0, false
	}
	qe := e - 1
	q := lex.NameRunBefore(s, qe)
	if q == qe || q == 0 || (s[q-1] != '"' && s[q-1] != '\'') {
		return 0, 0, false
	}
	return q, qe, true
}

// jsonField: `"name": "value"` (the name between quotes at [q, qe)); the value keeps its
// quotes and loses its body; unclosed, it runs to the line end.
func (c *Scan) jsonField(q, qe, p int) {
	s := c.S
	name := lex.TrimDashes(s[q:qe])
	v := lex.SkipSpaceConts(s, p+1)
	if v >= len(s) || (s[v] != '"' && s[v] != '\'') {
		return
	}
	next := lex.DqEndLine
	if s[v] == '\'' {
		next = lex.SqEndEsc
	}
	end := c.R.QuotedEnd(s, v, next)
	if !judged(name, s[v:end]) {
		return
	}
	// Closed only when the scan stopped on its own closing quote, not an escaped one.
	body := end
	if end > v+1 && s[end-1] == s[v] && !escapedAt(s, end-1) {
		body = end - 1
	}
	// A receiver reads the field's value to its quote: `<redacted>` alone is hidden, anything
	// else (a placeholder and a blank, or more) is a value partly sent.
	if inner := strings.TrimRight(s[v+1:end], s[v:v+1]); inner == "" || inner == lex.PhRedacted {
		return
	}
	c.Hide(v+1, body, span.KindSecret)
}

// escapedAt: the character at i is escaped by an odd run of backslashes before it.
func escapedAt(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// objectAfter: the object a credential's name holds goes whole, to its matching brace.
func (c *Scan) objectAfter(name string, p int) {
	s := c.S
	v := lex.SkipSpaceConts(s, p+1)
	if v >= len(s) || s[v] != '{' || (v+1 < len(s) && s[v+1] == '{') || !vocab.IsCredentialName(name) {
		return
	}
	end := lex.ObjectEnd(s, v+1)
	if end > v+1 && s[end-1] == '}' {
		end--
	}
	c.hideValue(v+1, end)
}

// schemeAssigned: an assignment written after an auth scheme word (`Token password:x`).
func (c *Scan) schemeAssigned(q int, name string, p int) {
	s := c.S
	j := q
	for j > 0 {
		if s[j-1] == ' ' || s[j-1] == '\t' {
			j--
			continue
		}
		if j >= 2 && s[j-1] == '\n' && s[j-2] == '\\' {
			j -= 2
			continue
		}
		break
	}
	if j == q {
		return
	}
	w := j
	for w > 0 && (lex.IsAlnumASCII(s[w-1]) || s[w-1] == '-') {
		w--
	}
	word := strings.ToLower(s[w:j])
	if !(lex.AuthSchemes[word] || word == "apikey" || word == "api-key") {
		return
	}
	if w > 0 && (lex.IsLowerASCII(s[w-1]) || lex.IsUpperASCII(s[w-1])) {
		return
	}
	if !vocab.IsCredentialName(name) {
		return
	}
	vs := p + 1
	k := vs
	for k < len(s) && s[k] == '=' {
		k++
	}
	if k >= len(s) || lex.IsSpaceByte(s[k]) {
		return
	}
	c.hideValue(vs, lex.ValueEnd(s, vs))
}
