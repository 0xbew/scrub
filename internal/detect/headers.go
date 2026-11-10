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
			k := SkipConts(s, j)
			if k < len(s) && !lex.IsSpaceByte(s[k]) && s[k] != '"' && s[k] != '\'' {
				j = k
				continue
			}
			return j
		}
		ch := s[j]
		if ch == '\\' {
			k := j
			for k < len(s) && s[k] == '\\' {
				k++
			}
			if k < len(s) && s[k] == ' ' {
				j = k + 1
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
				out = append(out, j)
				break
			}
			if s[j] == '\n' || s[j] == '\\' {
				break
			}
			j++
		}
	case `'`:
		j := from
		for j < len(s) {
			if n := lex.ContAt(s, j); n > 0 {
				j += n
				continue
			}
			if s[j] == '\'' {
				out = append(out, j)
				break
			}
			if s[j] == '\n' {
				break
			}
			j++
		}
	case `\"`:
		j := from
		for j < len(s) {
			if n := lex.ContAt(s, j); n > 0 {
				j += n
				continue
			}
			if s[j] == '\\' && j+1 < len(s) && s[j+1] == '"' {
				out = append(out, j)
				break
			}
			if s[j] == '"' || s[j] == '\n' {
				break
			}
			j++
		}
	}
	// The last reading: the first quote of either kind, when it is the opening one.
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
					out = append(out, j-1)
				}
			} else {
				out = append(out, j)
			}
		}
	}
	return out
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
	// Any credential's name as a header after -H / --header.
	for _, flag := range []string{"-H", "--header"} {
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
			j := f + len(flag)
			if j < len(s) && s[j] == '=' {
				j++
			} else {
				e := lex.SkipBlanks(s, j)
				if e == j {
					continue
				}
				j = e
			}
			if j < len(s) && s[j] == '\\' && j+1 < len(s) && s[j+1] == '"' {
				j += 2
			} else if j < len(s) && (s[j] == '"' || s[j] == '\'') {
				j++
			}
			j = lex.SkipBlanks(s, j)
			ne := lex.NameRunAfter(s, j)
			if ne == j || !vocab.IsCredentialName(s[j:ne]) {
				continue
			}
			c.headerValue(j, ne, "", false)
		}
	}
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
	closed := false
	if open != "" {
		// The quoted reading takes the blanks after the colon with the value.
		colon := strings.IndexByte(s[ne:], ':') + ne
		for _, cl := range closingQuotes(s, ne, open) {
			if cl > v {
				c.hideValue(colon+1, cl)
			}
			closed = true
		}
	}
	// An outer quote that never closes, around a value that opens the other quote
	// (`-H 'X-Api-Key:"V"`): the value is that quoted part.
	if open != "" && !closed && v < len(s) && (s[v] == '"' || s[v] == '\'') {
		_, e := lex.CrudeValue(s, v)
		c.hideQuotedBody(v, e)
	}
	// A known header in an object literal: its value's own `, k=v` parameters (Digest, SigV4)
	// read as the literal's next fields, so the value runs to the line end.
	if _, flow, tight := colonContext(s, q); fixed && (flow || tight) && open == "" {
		le := ContLineEnd(s, v)
		if le > v && !lex.OnlyPlaceholders(s[v:le]) {
			c.Hide(v, le, span.KindSecret)
			return
		}
	}
	// Unquoted, a value that opens a quoted part (`X-Token:'abc'`) is the shell word it starts. A
	// header name read inside a longer one (`api-key` in `'X-Api-Key:'`) is not unquoted.
	if open == "" && (q == 0 || !lex.IsNameChar(s[q-1])) && v < len(s) && (s[v] == '"' || s[v] == '\'') {
		c.hideQuotedBody(v, lex.ValueEnd(s, v))
	}
	switch {
	case h == "cookie":
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
		c.hideValue(v, end)
	case h == "authorization" || h == "proxy-authorization":
		end := hwordEnd(s, v, false)
		word := strings.ToLower(s[v:end])
		if lex.AuthSchemes[word] || word == "aws4-hmac-sha256" {
			k := v + len(word)
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
			if sep > k {
				if e := hwordEnd(s, sep, false); e > sep {
					end = e
				}
			}
		}
		c.hideValue(v, end)
	default:
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
		c.hideValue(v, end)
	}
}
