package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

var bearerProse = lex.SetOf("token", "tokens", "auth", "authentication", "authorization", "credential", "credentials", "jwt",
	"jwts", "scheme", "header", "bearer")

func isBearerChar(ch byte) bool {
	return lex.IsAlnumASCII(ch) || ch == '.' || ch == '_' || ch == '~' || ch == '+' || ch == '/' || ch == '-'
}

// bearer: the word after a Bearer scheme, unless it is prose ("a Bearer token.").
func (c *Scan) bearer() {
	s := c.S
	low := lex.AsciiLower(s)
	for at := 0; ; {
		k := strings.Index(low[at:], "bearer")
		if k < 0 {
			return
		}
		b := at + k
		at = b + 1
		j := b + 6
		v := lex.SkipSpaceConts(s, j)
		if v == j || v >= len(s) {
			continue
		}
		// prose: the next word is one of these and nothing token-like follows it
		w := v
		for w < len(s) && lex.IsAlnumASCII(s[w]) {
			w++
		}
		if bearerProse[strings.ToLower(s[v:w])] {
			after := w
			tokenish := after < len(s) && (lex.IsAlnumASCII(s[after]) || strings.IndexByte("_~+/-=", s[after]) >= 0)
			if !tokenish && after+1 < len(s) && s[after] == '.' && isBearerChar(s[after+1]) && s[after+1] != '.' {
				tokenish = true
			}
			if !tokenish {
				continue
			}
		}
		e := v
		for e < len(s) {
			if isBearerChar(s[e]) {
				e++
				continue
			}
			if n := lex.ContAt(s, e); n > 0 {
				k := SkipConts(s, e)
				if k < len(s) && isBearerChar(s[k]) {
					e = k
					continue
				}
			}
			break
		}
		if e == v {
			continue
		}
		for e < len(s) && s[e] == '=' {
			e++
		}
		c.hideValue(v, e)
	}
}
