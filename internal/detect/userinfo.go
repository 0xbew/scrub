package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// --- URL userinfo -------------------------------------------------------------------------

func (c *Scan) userinfo() {
	s := c.S
	for at := 0; ; {
		k := strings.Index(s[at:], "://")
		if k < 0 {
			return
		}
		p := at + k + 3
		at = p
		// user: to the first colon; no `/`, space, `@` or bare backslash-newline
		j := p
		for j < len(s) {
			if n := lex.ContAt(s, j); n > 0 {
				j += n
				continue
			}
			ch := s[j]
			if ch == '/' || lex.IsSpaceByte(ch) || ch == ':' || ch == '@' {
				break
			}
			j++
		}
		// An empty user (`redis://:password@host`) still has a password.
		if j >= len(s) || s[j] != ':' {
			continue
		}
		v := j + 1
		e := SkipConts(s, v)
		for e < len(s) {
			if n := lex.ContAt(s, e); n > 0 {
				e += n
				continue
			}
			ch := s[e]
			if ch == '@' || lex.IsSpaceByte(ch) {
				break
			}
			e++
		}
		if e >= len(s) || s[e] != '@' || e == SkipConts(s, v) {
			continue
		}
		// A host never holds `@`, so a later `@` in the same URL is still the password's (`user:p@ss@host`), even past
		// a `/` `?` or `#` a password may hold unencoded: the last one is the delimiter. One that opens a path
		// segment (`/@scope`) is the path's; a blank, a quote or a closing bracket ends the URL.
		for n := e + 1; n < len(s); n++ {
			ch := s[n]
			if ch == '@' && s[n-1] != '/' {
				e = n
				continue
			}
			if lex.IsSpaceByte(ch) || strings.IndexByte("\"'`<>[]()", ch) >= 0 {
				break
			}
		}
		c.hideValue(v, e)
	}
}
