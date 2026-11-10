package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// ColonStop: what ends a several-word value: a comment, a default, a flag, or what closes
// the field.
func ColonStop(s string, i int) bool {
	if i >= len(s) {
		return true
	}
	switch s[i] {
	case '#', '=', ',', ';', '}', ']', '-':
		return true
	case '/':
		return i+1 < len(s) && s[i+1] == '/'
	}
	return false
}

var typeWords = []string{"str", "bytes", "int", "float", "bool", "None", "Any", "Optional", "Union", "SecretStr", "string",
	"number", "boolean", "undefined"}

// IsTypeWord: a type annotation's word at i (`token: str`).
func IsTypeWord(s string, i int) bool {
	for _, w := range typeWords {
		if len(s)-i >= len(w) && strings.EqualFold(s[i:i+len(w)], w) && !lex.IsWordAt(s, i+len(w)) {
			return true
		}
	}
	return false
}

// IsBlockIndicator: a YAML block scalar's `|` or `>` ends the line (`key: |`).
func IsBlockIndicator(s string, i int) bool {
	j := i
	for j < len(s) && (s[j] == '!' || s[j] == '&') {
		for j < len(s) && !lex.IsSpaceByte(s[j]) {
			j++
		}
		k := lex.SkipBlanks(s, j)
		if k == j {
			return false
		}
		j = k
	}
	if j >= len(s) || (s[j] != '|' && s[j] != '>') {
		return false
	}
	j++
	for j < len(s) && (s[j] == '-' || s[j] == '+' || lex.IsDigitASCII(s[j])) {
		j++
	}
	j = lex.SkipBlanks(s, j)
	if j < len(s) && s[j] == '#' {
		j = lex.LineEnd(s, j)
	}
	if j < len(s) && s[j] == '\r' {
		j++
	}
	return j >= len(s) || s[j] == '\n'
}

// colonContext: where a `name: value` may stand: first on its line (after blanks, a diff
// marker or a list dash), or after `{` or `,`.
func colonContext(s string, q int) (lineHead, flow, flowTight bool) {
	ls := lex.LineStart(s, q)
	lineHead = strings.Trim(s[ls:q], " \t+-") == "" || quotedHead(s, ls, q)
	j := q
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '+' || s[j-1] == '-') {
		j--
	}
	flow = j > 0 && (s[j-1] == '{' || s[j-1] == ',')
	k := q
	for k > 0 && (s[k-1] == ' ' || s[k-1] == '\t') {
		k--
	}
	flowTight = k > 0 && (s[k-1] == '{' || s[k-1] == ',')
	return
}

// quotedHead: the name at q opens a quoted string, blanks or a list dash between (`'  token: x'`,
// `"\"password: x\""`, `echo "- secret: x"`): the string's receiver reads it as a line of its own.
func quotedHead(s string, ls, q int) bool { return quotedHeadCloser(s, ls, q) != "" }

// quotedHeadCloser: for a quoted head, the quote as written that closes the innermost string (`'`, `\"`); else "".
func quotedHeadCloser(s string, ls, q int) string {
	k := q
	for k > ls && (s[k-1] == ' ' || s[k-1] == '\t' || s[k-1] == '-') {
		k--
	}
	n := 0
	closer := ""
	for k > ls && (s[k-1] == '"' || s[k-1] == '\'') {
		e := k
		k--
		n++
		for k > ls && s[k-1] == '\\' {
			k--
		}
		if closer == "" {
			closer = s[k:e]
		}
	}
	if n == 0 || (k > ls && !(lex.IsSpaceByte(s[k-1]) || strings.IndexByte("=([,", s[k-1]) >= 0)) {
		return ""
	}
	// The outermost quote opens a string: its kind stands an even number of times before it on the line.
	open := s[k]
	for open == '\\' && k < q {
		k++
		open = s[k]
	}
	if strings.Count(s[ls:k], string(open))%2 != 0 {
		return ""
	}
	return closer
}

// closerIndex: the first `cl` in s written as itself, not one escape level further down (`"` inside `\"`).
func closerIndex(s, cl string) int {
	for k := 0; k+len(cl) <= len(s); k++ {
		if strings.HasPrefix(s[k:], cl) && (k == 0 || s[k-1] != '\\') {
			return k
		}
	}
	return -1
}

// colonWords: a credential's value after `name:`: every word to a stop word; in an object
// literal a word ending in `,` `;` `}` `]` ends it.
func colonWords(s string, i int, flow, tight bool) int {
	next := func(j int) int {
		if tight {
			return lex.ValueEndFlow(s, j)
		}
		return lex.ValueEnd(s, j)
	}
	end := next(i)
	if end == i {
		return i
	}
	for {
		if flow && strings.IndexByte(",;}]", s[end-1]) >= 0 {
			return end
		}
		j := lex.SkipBlanks(s, end)
		if j == end || j >= len(s) || ColonStop(s, j) {
			return end
		}
		e := next(j)
		if e == j {
			return end
		}
		end = e
	}
}

// colon: `name: value` as YAML or an object literal writes it, `"name": value` as JSON,
// and the object a credential's name holds.
func (c *Scan) colon() {
	s := c.S
	for p := strings.IndexByte(s, ':'); p >= 0; p = lex.NextByte(s, ':', p+1) {
		// The name: blanks, then a run (possibly quoted) before the colon.
		e := p
		for e > 0 && (s[e-1] == ' ' || s[e-1] == '\t') {
			e--
		}
		quoted := false
		qe := e
		if e > 0 && (s[e-1] == '"' || s[e-1] == '\'') {
			quoted = true
			qe = e - 1
			for qe > 0 && s[qe-1] == '\\' {
				qe--
			}
		}
		q := lex.NameRunBefore(s, qe)
		if q == qe {
			// JSON with a line break or continuation before the colon.
			if jq, je, ok := c.quotedNameBeforeColon(p); ok {
				c.jsonField(jq, je, p)
			}
			continue
		}
		name := lex.TrimDashes(s[q:qe])
		if name == "" {
			continue
		}
		if quoted {
			if q > 0 && (s[q-1] == '"' || s[q-1] == '\'') {
				c.jsonField(q, qe, p)
				c.objectAfter(name, p)
			}
			continue
		} else {
			c.schemeAssigned(q, name, p)
		}
		lineHead, flow, tight := colonContext(s, q)
		if !lineHead && !flow && !tight {
			c.midColon(name, q, p)
			continue
		}
		// A head only a quoted string admits (`echo "password: x"`): one word, ended where the string closes (on
		// its line, or a continued one); an empty string, a `$` reference or an object holds no value here.
		if ls := lex.LineStart(s, q); lineHead && !flow && !tight && strings.Trim(s[ls:q], " \t+-") != "" {
			if cl := quotedHeadCloser(s, ls, q); cl != "" {
				v := lex.SkipBlanks(s, p+1)
				k := closerIndex(s[p+1:ContLineEnd(s, p)], cl)
				if v == p+1 || k < 0 || p+1+k <= v || s[v] == '$' || s[v] == '{' || IsTypeWord(s, v) {
					continue
				}
				end := lex.ValueEnd(s, v)
				if end > p+1+k {
					end = p + 1 + k
				}
				// The string's receiver reads a line of its own, so the name is judged as at a line's head.
				if judged(name, s[v:end]) {
					c.hideColonBody(v, end, false)
				}
			}
			continue
		}
		c.objectAfter(name, p)
		vs := p + 1
		spaced := vs < len(s) && (s[vs] == ' ' || s[vs] == '\t')
		if spaced && (lineHead || flow) {
			v := lex.SkipBlanks(s, vs)
			if v >= len(s) || IsTypeWord(s, v) || s[v] == '{' || IsBlockIndicator(s, v) {
				continue
			}
			c.colonValue(name, v, flow && !lineHead, false)
		} else if !spaced && tight {
			if vs >= len(s) || s[vs] == '{' || IsBlockIndicator(s, vs) || IsTypeWord(s, vs) {
				continue
			}
			c.colonValue(name, vs, true, true)
		}
	}
}
