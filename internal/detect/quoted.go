package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/span"
	"github.com/0xbew/scrub/internal/vocab"
)

// --- quoted words: fields and whole assignments ------------------------------------------

// quotedWords: the shell-quoted words, left to right: `"..."` with escapes, `'...'`
// without, each to its closing quote or its line's end.
func quotedWords(s string) [][2]int {
	var out [][2]int
	i := 0
	for i < len(s) {
		ch := s[i]
		if (ch == '"' || ch == '\'') && !(i > 0 && s[i-1] == '\\') {
			e := quotedWordEnd(s, i, ch)
			out = append(out, [2]int{i, e})
			i = e
			if i == out[len(out)-1][0] {
				i++
			}
			continue
		}
		i++
	}
	return out
}

// quotedWordEnd: the end of the word opened by the quote ch at i: past its closing quote, or
// at its line's end (for `"`, also at a `\` that ends the line or the text).
func quotedWordEnd(s string, i int, ch byte) int {
	var e int
	if ch == '"' {
		e = dqWordEnd(s, i)
	} else {
		le := lex.LineEnd(s, i+1)
		if k := strings.IndexByte(s[i+1:le], '\''); k >= 0 {
			e = i + 1 + k + 1
		} else {
			e = le
		}
	}
	return e
}

// dqWordEnd: the end of the `"` word at i, its escapes skipped: past its closing `"`, or at a
// line break, or at a `\` that ends the line or the text.
func dqWordEnd(s string, i int) int {
	e := i + 1
	for e < len(s) {
		if s[e] == '\\' && e+1 < len(s) && s[e+1] != '\n' {
			e += 2
			continue
		}
		if s[e] == '"' {
			e++
			break
		}
		if s[e] == '\\' || s[e] == '\n' {
			break
		}
		e++
	}
	return e
}

// quotedAssignments: a quoted word that opens with a credential's assignment holds the value
// to its closing quote (`"token=a b"`); a later `&name=` field in one does the same.
func (c *Scan) quotedAssignments() {
	s := c.S
	for _, w := range quotedWords(s) {
		a, b := w[0], w[1]
		q := s[a]
		inner := b
		if b > a+1 && s[b-1] == q {
			inner = b - 1
		}
		c.quotedWholeAssignment(a, inner, q)
		c.quotedFields(a, inner)
	}
	c.escapedQuoteAssignments()
	c.closedQuoteAssignments()
}

// quotedWholeAssignment: the quoted word opening at a (its body ending at inner) that opens with a credential's
// assignment, dashes before the name allowed, holds the value to its closing quote q.
func (c *Scan) quotedWholeAssignment(a, inner int, q byte) {
	s := c.S
	j := a + 1
	for j < inner && s[j] == '-' {
		j++
	}
	ne := lex.NameRunAfter(s, j)
	if ne > j && ne < len(s) && s[ne] == '=' && vocab.IsCredentialName(s[j:ne]) {
		c.hideWords(ne+1, assignedInQuotesEnd(s, ne+1, q))
	}
}

// quotedFields: each `&name=`, `?name=`, `;name=` or `,name=` field with a credential's name in the quoted word
// opening at a (its body ending at inner) holds its value to the word's closing quote.
func (c *Scan) quotedFields(a, inner int) {
	s := c.S
	for p := a + 1; p < inner; p++ {
		if s[p] != '=' {
			continue
		}
		nq := lex.NameRunBefore(s, p)
		if nq == p {
			continue
		}
		k := dottedNameStart(s, nq, a+1)
		if k <= a+1 || strings.IndexByte("&?;,", s[k-1]) < 0 {
			continue
		}
		if vocab.IsCredentialName(s[nq:p]) {
			// The field holds its value to the word's closing quote: a placeholder and
			// more (`?token=<redacted> +rest"`) is a value partly sent.
			c.hideWords(p+1, fieldEnd(s, p+1, inner))
		}
	}
}

// dottedNameStart: the start of the dotted name (`a.b.name`) whose last part starts at k, going back no
// further than lo.
func dottedNameStart(s string, k, lo int) int {
	for k > lo && s[k-1] == '.' {
		k2 := lex.NameRunBefore(s, k-1)
		if k2 == k-1 {
			break
		}
		k = k2
	}
	return k
}

// closedQuoteAssignments: `"NAME=value"` or `'NAME=value'` wherever a quote opens one, a quoted
// word inside another included (`'... "token=a b" ...'`, which the left-to-right reading pairs
// the other way): a closed quoted assignment holds its value to its closing quote.
func (c *Scan) closedQuoteAssignments() {
	s := c.S
	for i := 0; i < len(s); i++ {
		q := s[i]
		if (q != '"' && q != '\'') || (i > 0 && s[i-1] == '\\') {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] == '-' {
			j++
		}
		ne := lex.NameRunAfter(s, j)
		if ne == j || ne >= len(s) || s[ne] != '=' || !(lex.IsAlnumASCII(s[j]) || s[j] == '_') || !vocab.IsCredentialName(s[j:ne]) {
			continue
		}
		e := quotedValueEnd(s, ne+1, q)
		if e < len(s) && s[e] == q && e > ne+1 && !lex.PlaceholderValue(s[ne+1:e]) {
			c.Hide(ne+1, e, span.KindSecret)
		}
	}
}

// quotedValueEnd: where a value from e inside quote q stops: at q, a line break or the text's
// end, a backslash-escaped byte inside `"` skipped.
func quotedValueEnd(s string, e int, q byte) int {
	for e < len(s) && s[e] != '\n' && s[e] != q {
		if q == '"' && s[e] == '\\' && e+1 < len(s) && s[e+1] != '\n' {
			e += 2
			continue
		}
		e++
	}
	return e
}

// assignedInQuotesEnd: a whole assignment's value inside a quoted word: in double quotes an
// escape (a continuation too) is the value's, and it ends at the closing quote or the line
// end; in single quotes, at the closing quote or the line end.
func assignedInQuotesEnd(s string, i int, q byte) int {
	j := i
	for j < len(s) {
		if q == '"' && s[j] == '\\' {
			if j+2 < len(s) && s[j+1] == '\r' && s[j+2] == '\n' {
				j += 3
				continue
			}
			j += 2
			continue
		}
		if s[j] == q || s[j] == '\n' {
			break
		}
		j++
	}
	if j > len(s) {
		j = len(s)
	}
	return j
}

// fieldEnd: a value inside a quoted word, to the word's closing quote or a line break.
func fieldEnd(s string, i, limit int) int {
	j := i
	for j < limit {
		if s[j] == '\\' && j+1 < limit {
			j += 2
			continue
		}
		if s[j] == '\n' {
			return j
		}
		j++
	}
	if j > limit {
		j = limit
	}
	return j
}

// escapedQuoteAssignments: `\"token=a b\"`, a level down: to the next escaped quote.
func (c *Scan) escapedQuoteAssignments() {
	s := c.S
	for at := 0; ; {
		k := strings.Index(s[at:], `\"`)
		if k < 0 {
			return
		}
		p := at + k + 2
		at = p
		j := p
		for j < len(s) && s[j] == '-' {
			j++
		}
		ne := lex.NameRunAfter(s, j)
		if ne == j || ne >= len(s) || s[ne] != '=' || !vocab.IsCredentialName(s[j:ne]) {
			continue
		}
		e := ne + 1
		for e < len(s) && s[e] != '"' && s[e] != '\n' {
			e++
		}
		c.hideValue(ne+1, e)
	}
}
