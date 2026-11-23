package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/span"
	"github.com/0xbew/scrub/internal/vocab"
)

// --- headers and schemes (R3) ------------------------------------------------------------

var FixedHeaders = []string{"proxy-authorization", "authorization", "x-api-key", "api-key", "x-auth-token",
	"x-goog-api-key", "cookie"}

// hwordEnd: a header value's word: not a space, quote or backslash, except a backslash
// run before a space; continuations join.
func hwordEnd(s string, i int, cookie bool) int {
	j := i
	for j < len(s) {
		if n := lex.ContAt(s, j); n > 0 && j > i {
			if k := joinedAfterConts(s, j); k >= 0 {
				j = k
				continue
			}
			return j
		}
		ch := s[j]
		if ch == '\\' {
			if k := spacedBackslashEnd(s, j); k >= 0 {
				j = k
				continue
			}
			return j
		}
		if lex.IsSpaceByte(ch) || ch == '"' || ch == '\'' || (cookie && ch == ';') {
			return j
		}
		j++
	}
	return j
}

// joinedAfterConts: where a header word goes on after the continuations at j: the byte after
// them when it is not a space or quote; -1 when the word ends at them.
func joinedAfterConts(s string, j int) int {
	k := SkipConts(s, j)
	if k < len(s) && !lex.IsSpaceByte(s[k]) && s[k] != '"' && s[k] != '\'' {
		return k
	}
	return -1
}

// spacedBackslashEnd: past the space after the backslash run at j, which keeps a header word
// going; -1 when no space follows the run.
func spacedBackslashEnd(s string, j int) int {
	k := j
	for k < len(s) && s[k] == '\\' {
		k++
	}
	if k < len(s) && s[k] == ' ' {
		return k + 1
	}
	return -1
}

// headerSep: after a header's name: blanks, a colon, then blanks, line breaks or
// continuations; or `:\ `. Returns the value's start, or -1.
func headerSep(s string, i int) int {
	j := i
	for j < len(s) && lex.IsSpaceByte(s[j]) {
		j++
	}
	if j >= len(s) || s[j] != ':' {
		return -1
	}
	j++
	if strings.HasPrefix(s[j:], `\ `) {
		return j + 2
	}
	return lex.SkipSpaceConts(s, j)
}

// closingQuote: where a header quoted with `open` closes, reading as each quoting allows;
// every reading that closes is returned.
func closingQuotes(s string, from int, open string) []int {
	var out []int
	switch open {
	case `"`:
		if j := doubleQuoteClose(s, from); j >= 0 {
			out = append(out, j)
		}
	case `'`:
		if j := singleQuoteClose(s, from); j >= 0 {
			out = append(out, j)
		}
	case `\"`:
		if j := escapedQuoteClose(s, from); j >= 0 {
			out = append(out, j)
		}
	}
	if j := firstQuoteClose(s, from, open); j >= 0 {
		out = append(out, j)
	}
	return out
}

// doubleQuoteClose: the `"` that closes a double-quoted header from from, escapes skipped; -1 when the line, the
// text or a lone backslash ends it first.
func doubleQuoteClose(s string, from int) int {
	j := from
	for j < len(s) {
		if n := lex.ContAt(s, j); n > 0 {
			j += n
			continue
		}
		if s[j] == '\\' && j+1 < len(s) && s[j+1] != '\n' {
			j += 2
			continue
		}
		if s[j] == '"' {
			return j
		}
		if s[j] == '\n' || s[j] == '\\' {
			break
		}
		j++
	}
	return -1
}

// singleQuoteClose: the `'` that closes a single-quoted header from from; -1 when the line or the
// text ends first.
func singleQuoteClose(s string, from int) int {
	j := from
	for j < len(s) {
		if n := lex.ContAt(s, j); n > 0 {
			j += n
			continue
		}
		if s[j] == '\'' {
			return j
		}
		if s[j] == '\n' {
			break
		}
		j++
	}
	return -1
}

// escapedQuoteClose: the `\"` that closes a header opened with `\"` from from; -1 when a bare `"` or the line
// ends first.
func escapedQuoteClose(s string, from int) int {
	j := from
	for j < len(s) {
		if n := lex.ContAt(s, j); n > 0 {
			j += n
			continue
		}
		if s[j] == '\\' && j+1 < len(s) && s[j+1] == '"' {
			return j
		}
		if s[j] == '"' || s[j] == '\n' {
			break
		}
		j++
	}
	return -1
}

// firstQuoteClose: the last reading: the first quote of either kind from from, when it is the opening one;
// -1 otherwise.
func firstQuoteClose(s string, from int, open string) int {
	j := from
	for j < len(s) {
		if n := lex.ContAt(s, j); n > 0 {
			j += n
			continue
		}
		if s[j] == '"' || s[j] == '\'' || s[j] == '\n' {
			break
		}
		j++
	}
	if j < len(s) && s[j] != '\n' {
		q := open[len(open)-1]
		if s[j] == q {
			if len(open) == 2 {
				if j > 0 && s[j-1] == '\\' {
					return j - 1
				}
			} else {
				return j
			}
		}
	}
	return -1
}

// quoteBefore: the quote (and an escaping backslash) that opens the header at name start q.
func quoteBefore(s string, q int) string {
	j := q
	for j > 0 && lex.IsSpaceByte(s[j-1]) {
		j--
	}
	if j == 0 {
		return ""
	}
	if s[j-1] == '"' {
		if j >= 2 && s[j-2] == '\\' {
			return `\"`
		}
		return `"`
	}
	if s[j-1] == '\'' {
		return `'`
	}
	return ""
}

func (c *Scan) headers() {
	c.fixedHeaders()
	// Any credential's name as a header after -H / --header.
	for _, flag := range []string{"-H", "--header"} {
		c.flagHeaders(flag)
	}
}

// fixedHeaders: every known header's name that stands as a word, and its value.
func (c *Scan) fixedHeaders() {
	s := c.S
	low := lex.AsciiLower(s)
	for _, h := range FixedHeaders {
		for at := 0; ; {
			k := strings.Index(low[at:], h)
			if k < 0 {
				break
			}
			q := at + k
			at = q + 1
			if q > 0 && lex.WordBefore(s, q) {
				continue
			}
			c.headerValue(q, q+len(h), h, true)
		}
	}
}

// flagHeaders: every header flag `flag` that stands as a word, and the credential's name it
// passes as a header with its value.
func (c *Scan) flagHeaders(flag string) {
	s := c.S
	for at := 0; ; {
		k := strings.Index(s[at:], flag)
		if k < 0 {
			break
		}
		f := at + k
		at = f + 1
		if f > 0 && (lex.WordBefore(s, f) || s[f-1] == '-') {
			continue
		}
		c.flagHeaderAt(f, flag)
	}
}

// flagHeaderAt: the header flag `flag` at f, when its value starts with a credential's name.
func (c *Scan) flagHeaderAt(f int, flag string) {
	s := c.S
	j, ok := flagHeaderValueAt(s, f+len(flag))
	if !ok {
		return
	}
	ne := lex.NameRunAfter(s, j)
	if ne == j || !vocab.IsCredentialName(s[j:ne]) {
		return
	}
	c.headerValue(j, ne, "", false)
}

// flagHeaderValueAt: where a header flag's value starts, its flag ending at j: after an `=` or
// blanks, an opening quote (`\"`, `"` or `'`) and blanks; false when neither `=` nor a blank
// follows the flag.
func flagHeaderValueAt(s string, j int) (int, bool) {
	if j < len(s) && s[j] == '=' {
		j++
	} else {
		e := lex.SkipBlanks(s, j)
		if e == j {
			return 0, false
		}
		j = e
	}
	if j < len(s) && s[j] == '\\' && j+1 < len(s) && s[j+1] == '"' {
		j += 2
	} else if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		j++
	}
	j = lex.SkipBlanks(s, j)
	return j, true
}

// headerValue: the header named s[q:ne]; fixed tells a known header from a credential's name.
func (c *Scan) headerValue(q, ne int, h string, fixed bool) {
	s := c.S
	v := headerSep(s, ne)
	if v < 0 {
		return
	}
	if v >= 2 && s[v-2:v] == `\ ` {
		c.hideValue(v-2, v) // `name:\ value`: the escaped space goes with the value
	}
	open := quoteBefore(s, q)
	if open != "" {
		c.quotedHeaderValue(ne, v, open)
	}
	if c.objectLiteralHeader(q, v, open, fixed) {
		return
	}
	// Unquoted, a value that opens a quoted part (`X-Token:'abc'`) is the shell word it starts. A
	// header name read inside a longer one (`api-key` in `'X-Api-Key:'`) is not unquoted.
	if open == "" && (q == 0 || !lex.IsNameChar(s[q-1])) && v < len(s) && (s[v] == '"' || s[v] == '\'') {
		c.hideQuotedBody(v, lex.ValueEnd(s, v))
	}
	switch h {
	case "cookie":
		c.hideValue(v, cookieValueEnd(s, v))
	case "authorization", "proxy-authorization":
		c.hideValue(v, authorizationValueEnd(s, v))
	default:
		c.hideValue(v, headerWordValueEnd(s, v, fixed))
	}
}

// quotedHeaderValue: a header whose name ends at ne, inside the quote open, its value at v. The quoted reading takes the blanks
// after the colon with the value.
func (c *Scan) quotedHeaderValue(ne, v int, open string) {
	s := c.S
	closed := false
	colon := strings.IndexByte(s[ne:], ':') + ne
	for _, cl := range closingQuotes(s, ne, open) {
		if cl > v {
			c.hideValue(colon+1, cl)
		}
		closed = true
	}
	// An outer quote that never closes, around a value that opens the other quote
	// (`-H 'X-Api-Key:"V"`): the value is that quoted part.
	if !closed && v < len(s) && (s[v] == '"' || s[v] == '\'') {
		_, e := lex.CrudeValue(s, v)
		c.hideQuotedBody(v, e)
	}
}

// objectLiteralHeader: a known header in an object literal: its value's own `, k=v` parameters (Digest, SigV4)
// read as the literal's next fields, so the value runs to the line end. Reports whether it hid that value.
func (c *Scan) objectLiteralHeader(q, v int, open string, fixed bool) bool {
	s := c.S
	if _, flow, tight := colonContext(s, q); fixed && (flow || tight) && open == "" {
		le := ContLineEnd(s, v)
		if le > v && !lex.OnlyPlaceholders(s[v:le]) {
			c.Hide(v, le, span.KindSecret)
			return true
		}
	}
	return false
}

// cookieValueEnd: where a cookie header's value at v ends: its words joined by `;`.
func cookieValueEnd(s string, v int) int {
	end := hwordEnd(s, v, true)
	for end < len(s) && s[end] == ';' {
		k := lex.SkipBlanksConts(s, end+1)
		e := hwordEnd(s, k, true)
		if e == k {
			end++
			break
		}
		end = e
	}
	return end
}

// authorizationValueEnd: where an authorization header's value at v ends: a word, and the word after an auth
// scheme.
func authorizationValueEnd(s string, v int) int {
	end := hwordEnd(s, v, false)
	word := strings.ToLower(s[v:end])
	if lex.AuthSchemes[word] || word == "aws4-hmac-sha256" {
		k := v + len(word)
		sep := schemeSepEnd(s, k)
		if sep > k {
			if e := hwordEnd(s, sep, false); e > sep {
				end = e
			}
		}
	}
	return end
}

// schemeSepEnd: past the blanks, escaped spaces and continuations from k.
func schemeSepEnd(s string, k int) int {
	sep := k
	for sep < len(s) {
		if s[sep] == ' ' || s[sep] == '\t' {
			sep++
			continue
		}
		if strings.HasPrefix(s[sep:], `\ `) {
			sep += 2
			continue
		}
		if n := lex.ContAt(s, sep); n > 0 {
			sep += n
			continue
		}
		break
	}
	return sep
}

// headerWordValueEnd: where any other header's value at v ends: a word, and for a credential's name (not
// fixed) the word after an auth scheme.
func headerWordValueEnd(s string, v int, fixed bool) int {
	end := hwordEnd(s, v, false)
	if !fixed && lex.AuthSchemes[strings.ToLower(s[v:end])] {
		k := lex.SkipBlanks(s, end)
		if strings.HasPrefix(s[k:], `\ `) {
			k += 2
		}
		if k > end {
			if e := hwordEnd(s, k, false); e > k {
				end = e
			}
		}
	}
	return end
}
