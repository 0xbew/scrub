package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// code: assignments of a credential's name in source.
func (c *Scan) code() {
	c.lits = [2][]litSpan{}
	defer func() {
		c.litMerge(c.lits[0])
		c.litMerge(c.lits[1])
	}()
	s := c.S
	i := 0
	for i < len(s) {
		if !lex.IsNameChar(s[i]) || (i > 0 && lex.IsNameChar(s[i-1])) {
			i++
			continue
		}
		e := lex.NameRunAfter(s, i)
		runStart := i
		start := i
		// A removed diff row's `-` (or a flag's dashes) is not part of the name.
		for start < e && s[start] == '-' {
			start++
		}
		i = e
		if start == e {
			continue
		}
		name := s[start:e]
		cred := vocab.IsCredentialName(name)
		if !cred {
			continue
		}
		c.litRule = 0
		c.codeAssignment(start, e)
		// A quoted name keeps its dashes (`'-xToken', ...`): the quote is before them.
		c.litRule = 1
		c.quotedNameArgument(runStart, e)
		c.litRule = 0
		c.colonArray(e)
	}
	c.envLines()
	c.sql()
	c.blockScalars()
}

func (c *Scan) codeAssignment(start, e int) {
	s := c.S
	v := CodeOpAfter(s, e, true)
	if v < 0 {
		return
	}
	if lo, hi, ok := HeredocAt(s, v); ok {
		c.hideValue(lo, hi)
		// The rest of the opener's line is the statement too (`<<~EOS.strip + "x"`): its literals go.
		// The body starts on the next line, so the opener's line ends the statement.
		c.literalsTo(heredocOpenerEnd(s, v), lex.LineEnd(s, v), true)
		return
	}
	afterOpen := OpenersEnd(s, v)
	c.statementLiterals(afterOpen, start)
	// A bare value at a line start: every word to a stop word.
	ls := lex.LineStart(s, start)
	head := s[ls:start]
	head = strings.TrimRight(head, "\"'")
	if strings.Trim(head, " \t+-") == "" && !IsCodeValue(s, v) && !StartsPlaceholder(s, v) && !StartsLiteral(s, v) {
		if ee := escapedHeredocEnd(s, v); ee > v {
			c.hideValue(v, ee)
		} else if we := CodeWordEnd(s, v); we > v {
			end := we
			for {
				k := lex.SkipBlanks(s, end)
				if k == end || k >= len(s) || ColonStop(s, k) {
					break
				}
				ke := CodeWordEnd(s, k)
				if ke == k {
					break
				}
				end = ke
			}
			c.hideValue(v, end)
		}
	}
	// Anywhere: an array, an escaped heredoc, or one code word. A word that looks random is a value even with a
	// bracket after it in prose (`token = Q7MD4J9 (see above)`).
	a := afterOpen
	if StartsPlaceholder(s, a) {
		return
	}
	if IsCodeValue(s, a) {
		// A bracket after a blank is prose going on, not a call or an index (`token = Q7MD4J9 (see docs)`).
		if we := CodeWordEnd(s, a); we > a && strings.IndexAny(s[a:we], ".(:") < 0 &&
			(valueLike(s[a:we]) || vocab.StrongCredentialName(s[start:e]) && plainWord(s[a:we])) {
			if k := lex.SkipBlanks(s, we); vocab.LooksSecret(s[a:we]) || (k > we && k < len(s) && (s[k] == '(' || s[k] == '[')) {
				c.hideValue(a, we)
			}
		}
		return
	}
	if a < len(s) && s[a] == '[' {
		c.hideArray(a)
		return
	}
	if StartsLiteral(s, a) {
		return
	}
	if ee := escapedHeredocEnd(s, a); ee > a {
		c.hideValue(a, ee)
		return
	}
	if we := CodeWordEnd(s, a); we > a {
		c.hideValue(a, we)
	}
}

// hideArray: an array's elements, its brackets kept (bounded).
func (c *Scan) hideArray(a int) {
	s := c.S
	limit := a + 1 + 4000
	if limit > len(s) {
		limit = len(s)
	}
	end := ArrayEnd(s, a)
	if strings.TrimSpace(s[a+1:end]) != "" {
		c.hideValue(a+1, end)
	}
}

// ArrayEnd: the `]` that closes the array opening at a (strings skipped, so a `]` inside one
// does not end it, nested arrays counted), or 4000 characters on, or the text's end.
func ArrayEnd(s string, a int) int {
	limit := a + 1 + 4000
	if limit > len(s) {
		limit = len(s)
	}
	depth := 0
	for i := a + 1; i < limit; i++ {
		switch c := s[i]; c {
		case '"', '\'':
			j := i + 1
			for j < limit && s[j] != c && s[j] != '\n' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= limit || s[j] != c {
				continue // an unclosed quote is read as a character
			}
			i = j
		case '[':
			depth++
		case ']':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return limit
}

// quotedNameArgument: `getenv("API_KEY", "x")`, `define("TOKEN", "x")`.
func (c *Scan) quotedNameArgument(start, e int) {
	s := c.S
	b := start
	if b == 0 || (s[b-1] != '"' && s[b-1] != '\'') {
		return
	}
	// Any quoted name, whatever stands before its quote (`'"NAME", "x"'`, `f"NAME", "x"` too): the
	// audit refuses a live literal after one, so the scrubber hides it.
	k := e
	for k < len(s) && s[k] == '\\' {
		k++
	}
	if k >= len(s) || (s[k] != '"' && s[k] != '\'') {
		return
	}
	k = lex.SkipBlanks(s, k+1)
	if k >= len(s) || s[k] != ',' {
		return
	}
	c.statementLiterals(lex.SkipBlanks(s, k+1), start)
}

// colonArray: `name: [a, b]`.
func (c *Scan) colonArray(e int) {
	s := c.S
	k := e
	if k < len(s) && (s[k] == '"' || s[k] == '\'') {
		k++
	}
	k = lex.SkipBlanks(s, k)
	if k >= len(s) || s[k] != ':' {
		return
	}
	k = lex.SkipBlanks(s, k+1)
	if k < len(s) && s[k] == '[' && !StartsPlaceholder(s, k+1) {
		c.hideArray(k)
	}
}
