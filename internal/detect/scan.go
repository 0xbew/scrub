package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
)

// Scan runs the detectors over one reading.
type Scan struct {
	S   string
	R   *reading.Reading
	Out *span.Set
	// lits: the statement literals each credential's reading found, per rule, merged across
	// readings at the end of code() (litMerge).
	lits    [2][]litSpan
	litRule int
}

func (c *Scan) Hide(a, b int, k span.Kind) {
	if a < 0 {
		a = 0
	}
	if b > len(c.S) {
		b = len(c.S)
	}
	if a >= b {
		return
	}
	lo, hi := c.R.Source(a, b)
	c.Out.Add(lo, hi, k)
}

// sourceText: the source text a reading span came from (an encoded value as written).
func (c *Scan) sourceText(a, b int) string {
	lo, hi := c.R.Source(a, b)
	if c.R.Src == "" || hi > len(c.R.Src) {
		return c.S[a:b]
	}
	return c.R.Src[lo:hi]
}

// hideValue hides s[a:b] unless it is already entirely placeholders.
func (c *Scan) hideValue(a, b int) {
	if a >= b || (lex.OnlyPlaceholders(c.S[a:b]) || HeldOnlyAt(c.S, a, b)) && !otherKindPlaceholder(c.S[a:b]) {
		return
	}
	c.Hide(a, b, span.KindSecret)
}

// ContLineEnd: the end of the line at i, read on past each continuation (`\` then a line
// break), before a trailing carriage return.
func ContLineEnd(s string, i int) int {
	for {
		le := lex.LineEnd(s, i)
		if le < len(s) && le > i && s[le-1] == '\\' && !escapedAt(s, le-1) {
			i = le + 1
			continue
		}
		if le >= 2 && le < len(s) && s[le-1] == '\r' && s[le-2] == '\\' && !escapedAt(s, le-2) {
			i = le + 1
			continue
		}
		if le > i && s[le-1] == '\r' {
			le--
		}
		return le
	}
}

// hideWords hides s[a:b], a value read to a closing quote or a stop word, unless it is
// entirely placeholders: a placeholder and more words is a value partly sent.
func (c *Scan) hideWords(a, b int) {
	if a < b && (!lex.OnlyPlaceholders(c.S[a:b]) || otherKindPlaceholder(c.S[a:b])) {
		c.Hide(a, b, span.KindSecret)
	}
}

// otherKindPlaceholder: a credential's value holding another kind's placeholder (`[email]`, `<redacted> [phone]`):
// only a secret's placeholder stands for a hidden value, so a receiver reads the other as the value left, and the
// value goes whole.
func otherKindPlaceholder(v string) bool {
	for i := strings.IndexByte(v, '['); i >= 0; i = lex.NextByte(v, '[', i+1) {
		if lex.PlaceholderAt(v, i) > 0 {
			return true
		}
	}
	return false
}

// heldOnly: a value that is a placeholder already written, then a quote and what is glued
// on, holding nothing but placeholders and quotes: scrubbed text, read again. A quote after
// the placeholder that closes one opened earlier on its line ends the value; one that opens
// a part takes that part into it (`password=<redacted>"hunter2"` is a value left).
func heldOnly(v string) bool { return HeldOnlyAt(v, 0, len(v)) }

func HeldOnlyAt(s string, a, b int) bool {
	n := lex.PlaceholderAt(s, a)
	if n == 0 {
		return false
	}
	end := a + n
	q := end
	for q < b && s[q] == '\\' {
		q++
	}
	if q >= b || (s[q] != '"' && s[q] != '\'') {
		return end == b || (end < b && isGluedBreak(s[end]))
	}
	quote := s[end : q+1]
	start := end
	if closesOnLine(s, end, quote) {
		start = q + 1
	}
	at := start
	for at < b {
		e := gluedPartEnd(s, at, b)
		if e == at {
			break
		}
		at = e
	}
	for i := start; i < at; {
		if m := lex.PlaceholderAt(s, i); m > 0 {
			i += m
			continue
		}
		if s[i] == '"' || s[i] == '\'' || s[i] == '\\' {
			i++
			continue
		}
		return false
	}
	return true
}

func isGluedBreak(c byte) bool { return lex.IsSpaceByte(c) || strings.IndexByte(")]},;|&>`", c) >= 0 }

// closesOnLine: an odd number of `quote` (unescaped) before end on its line.
func closesOnLine(s string, end int, quote string) bool {
	ls := lex.LineStart(s, end)
	if end-ls > 4096 {
		return false
	}
	n := 0
	for i := ls; i+len(quote) <= end; i++ {
		if s[i:i+len(quote)] == quote && (i == 0 || s[i-1] != '\\') {
			n++
			i += len(quote) - 1
		}
	}
	return n%2 == 1
}

// gluedPartEnd: one part of a shell word at i: a placeholder, a quoted part (raw or escaped,
// to its closing quote or the line end), or a run up to a word break.
func gluedPartEnd(s string, i, b int) int {
	if n := lex.PlaceholderAt(s, i); n > 0 {
		return i + n
	}
	j := i
	for j < b && s[j] == '\\' {
		j++
	}
	if j < b && (s[j] == '"' || s[j] == '\'') {
		q := s[j]
		k := j + 1
		for k < b && s[k] != '\n' {
			if q == '"' && s[k] == '\\' && k+1 < b && j == i {
				k += 2
				continue
			}
			if s[k] == q {
				return k + 1
			}
			k++
		}
		return k
	}
	j = i
	for j < b && !isGluedBreak(s[j]) && s[j] != '"' && s[j] != '\'' {
		if s[j] == '\\' {
			k := j
			for k < b && s[k] == '\\' {
				k++
			}
			if k < b && (s[k] == '"' || s[k] == '\'') {
				break
			}
			j = k
			continue
		}
		j++
	}
	return j
}

// extendEncoded: an encoded value as written runs on over the characters the decoded
// reading split it at (`abc+rest`), to a space, a quote or an encoded space or quote.
func (c *Scan) extendEncoded(a, b int) {
	src := c.R.Src
	if src == "" || a >= b {
		return
	}
	lo, hi := c.R.Source(a, b)
	if hi > len(src) {
		return
	}
	v := src[lo:hi]
	if strings.HasPrefix(v, "%22") || strings.HasPrefix(v, "%27") || strings.HasPrefix(v, "\"") || strings.HasPrefix(v, "'") {
		return
	}
	e := hi
	for e < len(src) && !lex.IsSpaceByte(src[e]) && src[e] != '"' && src[e] != '\'' {
		if src[e] == '%' && e+2 < len(src) {
			code := strings.ToUpper(src[e+1 : e+3])
			if code == "20" || code == "22" || code == "27" || code == "0A" || code == "0D" {
				break
			}
		}
		e++
	}
	if e > hi && !heldOnly(src[lo:e]) {
		c.Out.Add(lo, e, span.KindSecret)
	}
}

// hideQuotedBody hides a value, keeping a closed pair of quotes around it.
func (c *Scan) hideQuotedBody(a, b int) {
	v := c.S[a:b]
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'' || v[0] == '`') && v[len(v)-1] == v[0] {
		c.hideValue(a+1, b-1)
		return
	}
	if len(v) >= 1 && (v[0] == '"' || v[0] == '\'') {
		c.hideValue(a+1, b)
		return
	}
	c.hideValue(a, b)
}
