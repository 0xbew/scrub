package detect

import (
	"regexp"
	"sort"
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

var codeKeywordRx = regexp.MustCompile(`^(?i:(?:none|null|nil|true|false|undefined|this|self|nan))`)

var codeLeadRx = regexp.MustCompile(`^(?i:(?:await|new|lambda|yield|async|typeof|not|function|fn))`)

func isIdentStart(c byte) bool {
	return lex.IsLowerASCII(c) || lex.IsUpperASCII(c) || c == '_' || c == '$'
}

func isIdentChar(c byte) bool { return lex.IsAlnumASCII(c) || c == '_' || c == '$' }

// IsCodeValue: a value that is code, not a literal: a call, an index, a member, a keyword,
// a query parameter.
func IsCodeValue(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	rest := s[i:]
	if m := codeKeywordRx.FindString(rest); m != "" {
		n := i + len(m)
		if n >= len(s) || !(isIdentChar(s[n]) || s[n] == '.' || lex.IsWordAt(s, n)) {
			return true
		}
	}
	if m := codeLeadRx.FindString(rest); m != "" {
		if !lex.IsWordAt(s, i+len(m)) {
			return true
		}
	}
	switch s[i] {
	case '?':
		return i+1 >= len(s) || !(isIdentChar(s[i+1]) || lex.IsWordAt(s, i+1))
	case '$':
		j := i + 1
		for j < len(s) && lex.IsDigitASCII(s[j]) {
			j++
		}
		return j > i+1 && !lex.IsWordAt(s, j)
	case '%':
		return i+1 < len(s) && s[i+1] == 's' && !lex.IsWordAt(s, i+2)
	case ':':
		return i+1 < len(s) && (lex.IsLowerASCII(s[i+1]) || lex.IsUpperASCII(s[i+1]) || s[i+1] == '_')
	}
	if !isIdentStart(s[i]) {
		return false
	}
	j := i
	parts := 0
	for {
		if j >= len(s) || !isIdentStart(s[j]) {
			break
		}
		for j < len(s) && (isIdentChar(s[j]) || (s[j] >= 0x80 && lex.IsWordAt(s, j))) {
			j++
		}
		parts++
		m := memberLen(s, j)
		if m == 0 || j+m >= len(s) || !isIdentStart(s[j+m]) {
			break
		}
		j += m
	}
	k := lex.SkipBlanks(s, j)
	if k < len(s) && (s[k] == '(' || s[k] == '[') {
		return true
	}
	return parts > 1 && !(j < len(s) && (isIdentChar(s[j]) || lex.IsWordAt(s, j)))
}

func memberLen(s string, j int) int {
	switch {
	case strings.HasPrefix(s[j:], "::"), strings.HasPrefix(s[j:], "->"), strings.HasPrefix(s[j:], "?."):
		return 2
	case strings.HasPrefix(s[j:], "."):
		return 1
	}
	return 0
}

// StartsLiteral: a value that opens a literal, an escaped quote, or a bracket.
func StartsLiteral(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	if strings.IndexByte("\"'`[({\\", s[i]) >= 0 {
		return true
	}
	j := i
	for j < len(s) && j-i < 2 && strings.IndexByte("rRbBuUfFnNeE", s[j]) >= 0 {
		j++
	}
	if j == i {
		return false
	}
	for j < len(s) && s[j] == '\\' {
		j++
	}
	return j < len(s) && (s[j] == '"' || s[j] == '\'' || s[j] == '`')
}

// StartsPlaceholder: a value already redacted, perhaps behind a literal's opening.
func StartsPlaceholder(s string, i int) bool {
	j := i
	for j < len(s) && j-i < 2 && strings.IndexByte("rRbBuUfFnNeE", s[j]) >= 0 {
		j++
	}
	for j < len(s) && s[j] == '\\' {
		j++
	}
	if j < len(s) && (s[j] == '"' || s[j] == '\'' || s[j] == '`') {
		j++
	}
	return strings.HasPrefix(s[j:], "<redacted>") || strings.HasPrefix(s[j:], "<long-token>")
}

// CodeWordEnd: `[^\s;,)\]}#"'`\\]+`.
func CodeWordEnd(s string, i int) int {
	j := i
	for j < len(s) && !lex.IsSpaceByte(s[j]) && strings.IndexByte(";,)]}#\"'`\\", s[j]) < 0 {
		j++
	}
	return j
}

// StatementEnd: the statement holding pos ends at its line's end, or a later line's while a
// bracket is open, a line ends in a continuation or the next line starts with an operator.
func StatementEnd(s string, pos int) int {
	start := lex.LineStart(s, pos)
	depth := 0
	end := pos
	for n := 0; n < maxStatementLines; n++ {
		nl := lex.NextByte(s, '\n', end)
		if nl < 0 {
			end = len(s)
		} else {
			end = nl
		}
		line := s[start:end]
		depth += strings.Count(line, "(") + strings.Count(line, "[") + strings.Count(line, "{") -
			strings.Count(line, ")") - strings.Count(line, "]") - strings.Count(line, "}")
		if depth < 0 {
			depth = 0
		}
		following := ""
		if nl >= 0 {
			following = strings.TrimLeft(s[nl+1:lex.LineEnd(s, nl+1)], " \t\n\r\f\v")
		}
		trimmed := strings.TrimRight(line, " \t\n\r\f\v")
		continues := trimmed != "" && strings.IndexByte("([{,\\+?:|&=", trimmed[len(trimmed)-1]) >= 0
		leads := following != "" && strings.IndexByte("+?:.|&)]}", following[0]) >= 0
		if nl < 0 || !(depth > 0 || continues || leads) {
			break
		}
		start = end + 1
		end = start
	}
	return end
}

// LiteralOpen: the next literal opener in s[from:to]: its start, the end of its opening, the
// backslashes before the quote and the quote.
func LiteralOpen(s string, from, to int) (start, open int, slashes, quote string, ok bool) {
	for i := from; i < to; i++ {
		ch := s[i]
		if ch != '"' && ch != '\'' && ch != '`' {
			continue
		}
		q := string(ch)
		if ch != '`' && i+2 < len(s) && s[i+1] == ch && s[i+2] == ch {
			q = strings.Repeat(q, 3)
		}
		b := i
		for b > from && s[b-1] == '\\' {
			b--
		}
		st := b
		for k := 0; k < 2 && st > from && strings.IndexByte("rRbBuUfFnNeE", s[st-1]) >= 0; k++ {
			st--
		}
		return st, i + len(q), s[b:i], q, true
	}
	return 0, 0, "", "", false
}

// LiteralEnd: just past a literal's closing quote, and the closing, or the statement end.
func LiteralEnd(s string, open int, slashes, quote string, end int) (int, string) {
	far := end
	if len(quote) == 3 || quote == "`" {
		far = open + maxLiteralChars
		if far > len(s) {
			far = len(s)
		}
	}
	if slashes != "" || len(quote) == 3 {
		at := open
		closing := slashes + quote
		for at < far {
			k := strings.Index(s[at:far], closing)
			if k < 0 {
				break
			}
			cl := at + k
			if slashes == "" || cl == 0 || s[cl-1] != '\\' {
				return cl + len(closing), closing
			}
			at = cl + 1
		}
		return end, ""
	}
	i := open
	for i < far {
		ch := s[i]
		switch {
		case ch == '\\':
			i += 2
		case string(ch) == quote:
			return i + 1, quote
		case ch == '\n' && quote != "`":
			return i, ""
		default:
			i++
		}
	}
	if i > end {
		i = end
	}
	return i, ""
}

// statementLiterals: every string literal from pos to the statement's end loses its body.
func (c *Scan) statementLiterals(pos, from int) {
	c.literalsTo(pos, StatementEnd(c.S, from), false)
}

// literalsTo: statementLiterals with the statement's end given; with hard, no literal reads
// past it.
func (c *Scan) literalsTo(pos, end int, hard bool) {
	s := c.S
	enclosing := ""
	prevEnd := -1
	for pos < end {
		st, open, slashes, quote, ok := LiteralOpen(s, pos, end)
		if !ok {
			return
		}
		if enclosing != "" && slashes == "" && quote == enclosing {
			return
		}
		if enclosing == "" && slashes != "" {
			enclosing = quote
		}
		cl, closing := LiteralEnd(s, open, slashes, quote, end)
		if hard && cl > end {
			cl, closing = end, ""
		}
		bodyEnd := cl - len(closing)
		// An unclosed literal of punctuation that closes brackets, opening right where the
		// previous literal closed (`'x'],` read with its closing quote as an opener), is the
		// statement's end, not a value. Any other unclosed literal's body goes.
		gluedToPrev := st == prevEnd
		if bodyEnd > open && strings.TrimSpace(s[open:bodyEnd]) != "" &&
			(closing != "" || hasWordChar(s[open:bodyEnd]) || !strings.ContainsAny(s[open:bodyEnd], ")]}") || !gluedToPrev) {
			if closing != "" {
				// A closed literal is one value to its closing quote: a placeholder and more words
				// in it is a value partly sent.
				c.hideWords(open, bodyEnd)
			} else {
				c.hideValue(open, bodyEnd)
			}
			c.lits[c.litRule] = append(c.lits[c.litRule], litSpan{st, cl, open - st, closing})
		}
		if closing != "" {
			prevEnd = cl
		} else {
			prevEnd = -1
		}
		if cl <= open {
			cl = open
		}
		pos = cl
		// An unclosed literal whose body is a placeholder already written paired a quote
		// wrongly: the statement's later literals are read on their own.
		if closing == "" && bodyEnd > open && HeldOnlyAt(s, open, bodyEnd) {
			pos = open
			continue
		}
		if pos == open && closing == "" && cl >= end {
			return
		}
	}
}

// litSpan: one literal a statement's reading found, opening quote (and prefix) to closing quote.
type litSpan struct {
	lo, hi  int
	opening int    // the opening's length: prefix letters, escapes and the quote
	closing string // "" when the literal never closed in its statement
}

// litMerge: each name's statement is read from that name, so two readings can pair the same
// quotes differently (a name inside a string reads its closing quote as an opener). Where their
// literals overlap they are one value, opening of the first to closing of the last, the quotes
// and what lies between included (scrub_literals.assignment_literals). An unclosed literal that
// starts inside another adds only when it reaches a word (`'x'),` is the statement's end).
func (c *Scan) litMerge(spans []litSpan) {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].lo != spans[j].lo {
			return spans[i].lo < spans[j].lo
		}
		return spans[i].hi > spans[j].hi
	})
	var merged []litSpan
	for _, sp := range spans {
		if n := len(merged); n > 0 && sp.lo < merged[n-1].hi {
			if sp.hi > merged[n-1].hi && (sp.closing != "" || hasWordChar(c.S[merged[n-1].hi:sp.hi])) {
				merged[n-1].hi, merged[n-1].closing = sp.hi, sp.closing
			}
			continue
		}
		merged = append(merged, sp)
	}
	for _, m := range merged {
		a, b := m.lo+m.opening, m.hi-len(m.closing)
		if m.closing != "" && !strings.HasSuffix(c.S[m.lo:m.hi], m.closing) || a >= b || strings.TrimSpace(c.S[a:b]) == "" {
			continue
		}
		if m.closing != "" {
			c.hideWords(a, b)
		} else {
			c.hideValue(a, b)
		}
	}
}
