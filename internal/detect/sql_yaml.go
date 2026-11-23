package detect

import (
	"regexp"
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

var EnvRx = regexp.MustCompile(`(?im)(?:^[ \t+-]*ENV|\bsetx)[ \t]+([A-Za-z0-9_-]+)[ \t]+`)

func (c *Scan) envLines() {
	s := c.S
	for _, m := range EnvRx.FindAllStringSubmatchIndex(s, -1) {
		if !vocab.IsCredentialName(s[m[2]:m[3]]) {
			continue
		}
		v := m[1]
		if v >= len(s) || s[v] == '=' || lex.IsSpaceByte(s[v]) {
			continue
		}
		c.hideValue(v, lex.LineEnd(s, v))
	}
}

var SqlKeyRx = regexp.MustCompile(`(?i)\b(?:PASSWORD(?:[ \t]+FOR[ \t]+\S+[ \t]*=)?|IDENTIFIED(?:[ \t]+WITH[ \t]+\w+)?[ \t]+BY(?:[ \t]+VALUES)?)\s+`)

var IdentifiedByRx = regexp.MustCompile(`(?i)\bIDENTIFIED[ \t]+BY[ \t]+`)

func (c *Scan) sql() {
	s := c.S
	for _, m := range SqlKeyRx.FindAllStringIndex(s, -1) {
		v := m[1]
		if v >= len(s) {
			continue
		}
		c.sqlValueAt(v)
	}
	for _, m := range IdentifiedByRx.FindAllStringIndex(s, -1) {
		c.identifiedByValueAt(m[1])
	}
}

// sqlValueAt: the value after a SQL key at v: the non-empty body of a quoted string (`'...'`,
// `"..."`, `E'...'`, `N'...'`) or of a dollar-quoted one, closed on its line.
func (c *Scan) sqlValueAt(v int) {
	s := c.S
	j := v
	if s[j] == 'E' || s[j] == 'e' || s[j] == 'N' || s[j] == 'n' {
		if j+1 < len(s) && s[j+1] == '\'' {
			j++
		}
	}
	switch {
	case s[j] == '\'' || s[j] == '"':
		q := s[j]
		k := sqlQuoteEnd(s, j, q)
		if k < len(s) && s[k] == q && k > j+1 {
			c.hideValue(j+1, k)
		}
	case strings.HasPrefix(s[j:], "$$"):
		k := strings.Index(s[j+2:lex.LineEnd(s, j+2)], "$$")
		if k > 0 {
			c.hideValue(j+2, j+2+k)
		}
	}
}

// sqlQuoteEnd: the closing quote q of the string opened at j, a doubled q read as one, or
// where its line ends.
func sqlQuoteEnd(s string, j int, q byte) int {
	k := j + 1
	for k < len(s) && s[k] != '\n' {
		if s[k] == q {
			if k+1 < len(s) && s[k+1] == q {
				k += 2
				continue
			}
			break
		}
		k++
	}
	return k
}

// identifiedByValueAt: the bare word after an `IDENTIFIED BY` that ends at v, unless it is the
// word `VALUES` or `PASSWORD`.
func (c *Scan) identifiedByValueAt(v int) {
	s := c.S
	up := strings.ToUpper(s[v:])
	if (strings.HasPrefix(up, "VALUES") && !lex.IsWordAt(s, v+6)) || (strings.HasPrefix(up, "PASSWORD") && !lex.IsWordAt(s, v+8)) {
		return
	}
	e := v
	for e < len(s) && !lex.IsSpaceByte(s[e]) && strings.IndexByte(";'\"$", s[e]) < 0 {
		e++
	}
	c.hideValue(v, e)
}

var blockHeadRx = regexp.MustCompile(`(?im)^([+-]?)([ \t]*)(?:-[ \t]+)?["']?([A-Za-z0-9_-]+)["']?[ \t]*:[ \t]*(?:[!&]\S*[ \t]+)*[|>][-+0-9]*[ \t]*(?:#[^\r\n]*)?\r?\n`)

// blockScalars: a YAML block scalar under a credential's name: every line after it indented
// deeper than the name's line.
func (c *Scan) blockScalars() {
	s := c.S
	for _, h := range blockHeadRx.FindAllStringSubmatchIndex(s, -1) {
		if !vocab.IsCredentialName(s[h[6]:h[7]]) {
			continue
		}
		marker := s[h[2]:h[3]]
		pos := h[1]
		following := s[pos:lex.LineEnd(s, pos)]
		if marker != "" && !strings.HasPrefix(following, marker) {
			marker = ""
		}
		line := s[h[0]:h[1]][len(marker):]
		depth := len(line) - len(strings.TrimLeft(line, " \t"))
		if end := blockScalarEnd(s, pos, marker, depth); end > h[1] {
			c.hideValue(h[1], end)
		}
	}
}

// blockScalarEnd: the end of the last non-blank line, from pos on, of a block scalar whose
// lines carry marker and sit deeper than depth; pos when there is none.
func blockScalarEnd(s string, pos int, marker string, depth int) int {
	end := pos
	for pos < len(s) {
		le := lex.LineEnd(s, pos)
		ln := strings.TrimRight(s[pos:le], "\r")
		if marker != "" && !strings.HasPrefix(ln, marker) {
			break
		}
		body := ln[len(marker):]
		if strings.TrimSpace(body) != "" {
			if len(body)-len(strings.TrimLeft(body, " \t")) <= depth {
				break
			}
			end = le
		}
		pos = le + 1
	}
	return end
}

func hasWordChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if lex.IsWordAt(s, i) {
			return true
		}
	}
	return false
}
