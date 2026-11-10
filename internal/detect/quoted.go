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
			var e int
			if ch == '"' {
				e = i + 1
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
			} else {
				le := lex.LineEnd(s, i+1)
				if k := strings.IndexByte(s[i+1:le], '\''); k >= 0 {
					e = i + 1 + k + 1
				} else {
					e = le
				}
			}
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
		// whole assignment
		j := a + 1
		for j < inner && s[j] == '-' {
			j++
		}
		ne := lex.NameRunAfter(s, j)
		if ne > j && ne < len(s) && s[ne] == '=' && vocab.IsCredentialName(s[j:ne]) {
			c.hideWords(ne+1, assignedInQuotesEnd(s, ne+1, q))
		}
		// fields
		for p := a + 1; p < inner; p++ {
			if s[p] != '=' {
				continue
			}
			nq := lex.NameRunBefore(s, p)
			if nq == p {
				continue
			}
			k := nq
			for k > a+1 && s[k-1] == '.' {
				k2 := lex.NameRunBefore(s, k-1)
				if k2 == k-1 {
					break
				}
				k = k2
			}
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
	c.escapedQuoteAssignments()
	c.closedQuoteAssignments()
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
		e := ne + 1
		for e < len(s) && s[e] != '\n' && s[e] != q {
			if q == '"' && s[e] == '\\' && e+1 < len(s) && s[e+1] != '\n' {
				e += 2
				continue
			}
			e++
		}
		if e < len(s) && s[e] == q && e > ne+1 && !lex.PlaceholderValue(s[ne+1:e]) {
			c.Hide(ne+1, e, span.KindSecret)
		}
	}
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
