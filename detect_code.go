package scrub

import (
	"regexp"
	"sort"
	"strings"
)

// Code: assignments in source (`password = "x"`, `token := x`, `:secret => x`,
// `api_key: str = x`, `var apiKey string = x`), an argument after a credential's quoted name
// (`getenv("API_KEY", "x")`), heredocs, YAML block scalars, SQL, Dockerfile ENV and setx.

const (
	maxStatementLines = 12
	maxLiteralChars   = 4000
)

// codeOpAfter: a code assignment operator after a name ending at e. Returns where the
// value starts (after the operator and a continuation), or -1. goType allows a type after
// a bare word (`name string =`), which the audit allows only after `var`.
func codeOpAfter(s string, e int, goType bool) int {
	k := e
	// The name may be quoted (a level down) and indexed: `os.environ["DB_PASSWORD"] = x`.
	for k < len(s) && s[k] == '\\' {
		k++
	}
	closedQuote := false
	if k < len(s) && (s[k] == '"' || s[k] == '\'') {
		k++
		closedQuote = true
	}
	if k < len(s) && s[k] == ']' {
		k++
		closedQuote = true
	}
	if !closedQuote {
		k = e
	}
	op := plainOp(s, k, closedQuote)
	if op < 0 {
		op = typedOp(s, k, goType)
	}
	if op < 0 && closedQuote {
		op = plainOp(s, e, false)
		if op < 0 {
			op = typedOp(s, e, goType)
		}
	}
	if op < 0 {
		return -1
	}
	// OP_TAIL: blanks, and a continuation then blanks and diff markers.
	j := skipBlanks(s, op)
	if n := contAt(s, j); n > 0 {
		j += n
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '+' || s[j] == '-') {
			j++
		}
	}
	return j
}

func notCompare(s string, i int) bool {
	return i >= len(s) || (s[i] != '=' && s[i] != '~' && s[i] != '>')
}

// plainOp: `:=` `=>` `?=` `+=` `||=` `&&=` `??=` (after blanks), ` =` (a blank before), `= `
// (a blank after), and `=` straight after a closing quote or bracket.
func plainOp(s string, k int, afterQuote bool) int {
	j := skipBlanks(s, k)
	for _, op := range []string{":=", "=>", "||=", "&&=", "??=", "?=", "+="} {
		if strings.HasPrefix(s[j:], op) {
			if (op == "?=" || op == "+=") && !notCompareEq(s, j+2) {
				continue
			}
			return j + len(op)
		}
	}
	if j < len(s) && s[j] == '=' && notCompare(s, j+1) {
		if j > k {
			return j + 1 // `[ \t]+=`
		}
		if j+1 < len(s) && (s[j+1] == ' ' || s[j+1] == '\t') {
			return j + 1
		}
		if afterQuote {
			return j + 1
		}
	}
	return -1
}

func notCompareEq(s string, i int) bool { return i >= len(s) || s[i] != '=' }

// typedOp: an annotation `: Type =` or (goType) a type after a blank `name T =`.
func typedOp(s string, k int, goType bool) int {
	j := skipBlanks(s, k)
	if j < len(s) && s[j] == ':' {
		t := skipBlanks(s, j+1)
		if t < len(s) && (s[t] == '"' || s[t] == '\'') {
			t++
		}
		if e := typeNameEnd(s, t, false); e > t {
			if e < len(s) && (s[e] == '"' || s[e] == '\'') {
				e++
			}
			e = subscriptEnd(s, e)
			o := skipBlanks(s, e)
			if o < len(s) && s[o] == '=' && notCompare(s, o+1) {
				return o + 1
			}
		}
		return -1
	}
	if goType && j > k {
		if e := typeNameEnd(s, j, true); e > j {
			e = subscriptEnd(s, e)
			o := skipBlanks(s, e)
			if o < len(s) && s[o] == '=' && notCompare(s, o+1) {
				return o + 1
			}
		}
	}
	return -1
}

func typeNameEnd(s string, i int, star bool) int {
	if i >= len(s) || !(isLowerASCII(s[i]) || isUpperASCII(s[i]) || s[i] == '_') {
		return i
	}
	j := i + 1
	for j < len(s) && (isWordAt(s, j) || s[j] == '.' || (star && s[j] == '*')) {
		j++
	}
	return j
}

// subscriptEnd: a bounded `[...]` one level nested (`dict[str, list[int]]`).
func subscriptEnd(s string, i int) int {
	if i >= len(s) || s[i] != '[' {
		return i
	}
	depth := 0
	for j := i; j < len(s) && j-i < 200; j++ {
		switch s[j] {
		case '[':
			depth++
			if depth > 2 {
				return i
			}
		case ']':
			depth--
			if depth == 0 {
				return j + 1
			}
		case '\n':
			return i
		}
	}
	return i
}

// openers: `(` or `{` after the operator, each perhaps followed by a line break and an
// indented next line.
func openersEnd(s string, i int) int {
	j := i
	for j < len(s) && (s[j] == '(' || s[j] == '{') {
		j = skipBlanks(s, j+1)
		k := j
		if k < len(s) && s[k] == '\r' {
			k++
		}
		if k < len(s) && s[k] == '\n' {
			k++
			for k < len(s) && (s[k] == ' ' || s[k] == '\t' || s[k] == '+' || s[k] == '-') {
				k++
			}
			j = k
		}
	}
	return j
}

var codeKeywordRx = regexp.MustCompile(`^(?i:(?:none|null|nil|true|false|undefined|this|self|nan))`)
var codeLeadRx = regexp.MustCompile(`^(?i:(?:await|new|lambda|yield|async|typeof|not|function|fn))`)

func isIdentStart(c byte) bool { return isLowerASCII(c) || isUpperASCII(c) || c == '_' || c == '$' }
func isIdentChar(c byte) bool  { return isAlnumASCII(c) || c == '_' || c == '$' }

// isCodeValue: a value that is code, not a literal: a call, an index, a member, a keyword,
// a query parameter.
func isCodeValue(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	rest := s[i:]
	if m := codeKeywordRx.FindString(rest); m != "" {
		n := i + len(m)
		if n >= len(s) || !(isIdentChar(s[n]) || s[n] == '.' || isWordAt(s, n)) {
			return true
		}
	}
	if m := codeLeadRx.FindString(rest); m != "" {
		if !isWordAt(s, i+len(m)) {
			return true
		}
	}
	switch s[i] {
	case '?':
		return i+1 >= len(s) || !(isIdentChar(s[i+1]) || isWordAt(s, i+1))
	case '$':
		j := i + 1
		for j < len(s) && isDigitASCII(s[j]) {
			j++
		}
		return j > i+1 && !isWordAt(s, j)
	case '%':
		return i+1 < len(s) && s[i+1] == 's' && !isWordAt(s, i+2)
	case ':':
		return i+1 < len(s) && (isLowerASCII(s[i+1]) || isUpperASCII(s[i+1]) || s[i+1] == '_')
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
		for j < len(s) && (isIdentChar(s[j]) || (s[j] >= 0x80 && isWordAt(s, j))) {
			j++
		}
		parts++
		m := memberLen(s, j)
		if m == 0 || j+m >= len(s) || !isIdentStart(s[j+m]) {
			break
		}
		j += m
	}
	k := skipBlanks(s, j)
	if k < len(s) && (s[k] == '(' || s[k] == '[') {
		return true
	}
	return parts > 1 && !(j < len(s) && (isIdentChar(s[j]) || isWordAt(s, j)))
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

// startsLiteral: a value that opens a literal, an escaped quote, or a bracket.
func startsLiteral(s string, i int) bool {
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

// startsPlaceholder: a value already redacted, perhaps behind a literal's opening.
func startsPlaceholder(s string, i int) bool {
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

// codeWordEnd: `[^\s;,)\]}#"'`\\]+`.
func codeWordEnd(s string, i int) int {
	j := i
	for j < len(s) && !isSpaceByte(s[j]) && strings.IndexByte(";,)]}#\"'`\\", s[j]) < 0 {
		j++
	}
	return j
}

// statementEnd: the statement holding pos ends at its line's end, or a later line's while a
// bracket is open, a line ends in a continuation or the next line starts with an operator.
func statementEnd(s string, pos int) int {
	start := lineStart(s, pos)
	depth := 0
	end := pos
	for n := 0; n < maxStatementLines; n++ {
		nl := nextByte(s, '\n', end)
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
			following = strings.TrimLeft(s[nl+1:lineEnd(s, nl+1)], " \t\n\r\f\v")
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

// literalOpen: the next literal opener in s[from:to]: its start, the end of its opening, the
// backslashes before the quote and the quote.
func literalOpen(s string, from, to int) (start, open int, slashes, quote string, ok bool) {
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

// literalEnd: just past a literal's closing quote, and the closing, or the statement end.
func literalEnd(s string, open int, slashes, quote string, end int) (int, string) {
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
func (c *scan) statementLiterals(pos, from int) {
	c.literalsTo(pos, statementEnd(c.s, from), false)
}

// literalsTo: statementLiterals with the statement's end given; with hard, no literal reads
// past it.
func (c *scan) literalsTo(pos, end int, hard bool) {
	s := c.s
	enclosing := ""
	prevEnd := -1
	for pos < end {
		st, open, slashes, quote, ok := literalOpen(s, pos, end)
		if !ok {
			return
		}
		if enclosing != "" && slashes == "" && quote == enclosing {
			return
		}
		if enclosing == "" && slashes != "" {
			enclosing = quote
		}
		cl, closing := literalEnd(s, open, slashes, quote, end)
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
		if closing == "" && bodyEnd > open && heldOnlyAt(s, open, bodyEnd) {
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
func (c *scan) litMerge(spans []litSpan) {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].lo != spans[j].lo {
			return spans[i].lo < spans[j].lo
		}
		return spans[i].hi > spans[j].hi
	})
	var merged []litSpan
	for _, sp := range spans {
		if n := len(merged); n > 0 && sp.lo < merged[n-1].hi {
			if sp.hi > merged[n-1].hi && (sp.closing != "" || hasWordChar(c.s[merged[n-1].hi:sp.hi])) {
				merged[n-1].hi, merged[n-1].closing = sp.hi, sp.closing
			}
			continue
		}
		merged = append(merged, sp)
	}
	for _, m := range merged {
		a, b := m.lo+m.opening, m.hi-len(m.closing)
		if m.closing != "" && !strings.HasSuffix(c.s[m.lo:m.hi], m.closing) || a >= b || strings.TrimSpace(c.s[a:b]) == "" {
			continue
		}
		if m.closing != "" {
			c.hideWords(a, b)
		} else {
			c.hideValue(a, b)
		}
	}
}

// code: assignments of a credential's name in source.
func (c *scan) code() {
	if off("code") {
		return
	}
	c.lits = [2][]litSpan{}
	defer func() {
		c.litMerge(c.lits[0])
		c.litMerge(c.lits[1])
	}()
	s := c.s
	i := 0
	for i < len(s) {
		if !isNameChar(s[i]) || (i > 0 && isNameChar(s[i-1])) {
			i++
			continue
		}
		e := nameRunAfter(s, i)
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
		cred := IsCredentialName(name)
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

func (c *scan) codeAssignment(start, e int) {
	s := c.s
	v := codeOpAfter(s, e, true)
	if v < 0 {
		return
	}
	if lo, hi, ok := heredocAt(s, v); ok {
		c.hideValue(lo, hi)
		// The rest of the opener's line is the statement too (`<<~EOS.strip + "x"`): its literals go.
		// The body starts on the next line, so the opener's line ends the statement.
		c.literalsTo(heredocOpenerEnd(s, v), lineEnd(s, v), true)
		return
	}
	afterOpen := openersEnd(s, v)
	c.statementLiterals(afterOpen, start)
	// A bare value at a line start: every word to a stop word.
	ls := lineStart(s, start)
	head := s[ls:start]
	head = strings.TrimRight(head, "\"'")
	if strings.Trim(head, " \t+-") == "" && !isCodeValue(s, v) && !startsPlaceholder(s, v) && !startsLiteral(s, v) {
		if ee := escapedHeredocEnd(s, v); ee > v {
			c.hideValue(v, ee)
		} else if we := codeWordEnd(s, v); we > v {
			end := we
			for {
				k := skipBlanks(s, end)
				if k == end || k >= len(s) || colonStop(s, k) {
					break
				}
				ke := codeWordEnd(s, k)
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
	if startsPlaceholder(s, a) {
		return
	}
	if isCodeValue(s, a) {
		// A bracket after a blank is prose going on, not a call or an index (`token = Q7MD4J9 (see docs)`).
		if we := codeWordEnd(s, a); we > a && strings.IndexAny(s[a:we], ".(:") < 0 &&
			(valueLike(s[a:we]) || strongCredentialName(s[start:e]) && plainWord(s[a:we])) {
			if k := skipBlanks(s, we); LooksSecret(s[a:we]) || (k > we && k < len(s) && (s[k] == '(' || s[k] == '[')) {
				c.hideValue(a, we)
			}
		}
		return
	}
	if a < len(s) && s[a] == '[' {
		c.hideArray(a)
		return
	}
	if startsLiteral(s, a) {
		return
	}
	if ee := escapedHeredocEnd(s, a); ee > a {
		c.hideValue(a, ee)
		return
	}
	if we := codeWordEnd(s, a); we > a {
		c.hideValue(a, we)
	}
}

// heredocOpenerEnd: just past a heredoc's opener (`<<-"EOF"`) at i.
func heredocOpenerEnd(s string, i int) int {
	j := i + 2
	if j < len(s) && (s[j] == '-' || s[j] == '~') {
		j++
	}
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		j++
	}
	for j < len(s) && isWordAt(s, j) {
		j++
	}
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		j++
	}
	return j
}

// hideArray: an array's elements, its brackets kept (bounded).
func (c *scan) hideArray(a int) {
	s := c.s
	limit := a + 1 + 4000
	if limit > len(s) {
		limit = len(s)
	}
	end := arrayEnd(s, a)
	if strings.TrimSpace(s[a+1:end]) != "" {
		c.hideValue(a+1, end)
	}
}

// arrayEnd: the `]` that closes the array opening at a (strings skipped, so a `]` inside one
// does not end it, nested arrays counted), or 4000 characters on, or the text's end.
func arrayEnd(s string, a int) int {
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
func (c *scan) quotedNameArgument(start, e int) {
	s := c.s
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
	k = skipBlanks(s, k+1)
	if k >= len(s) || s[k] != ',' {
		return
	}
	c.statementLiterals(skipBlanks(s, k+1), start)
}

// colonArray: `name: [a, b]`.
func (c *scan) colonArray(e int) {
	s := c.s
	k := e
	if k < len(s) && (s[k] == '"' || s[k] == '\'') {
		k++
	}
	k = skipBlanks(s, k)
	if k >= len(s) || s[k] != ':' {
		return
	}
	k = skipBlanks(s, k+1)
	if k < len(s) && s[k] == '[' && !startsPlaceholder(s, k+1) {
		c.hideArray(k)
	}
}

var envRx = regexp.MustCompile(`(?im)(?:^[ \t+-]*ENV|\bsetx)[ \t]+([A-Za-z0-9_-]+)[ \t]+`)

func (c *scan) envLines() {
	s := c.s
	for _, m := range envRx.FindAllStringSubmatchIndex(s, -1) {
		if !IsCredentialName(s[m[2]:m[3]]) {
			continue
		}
		v := m[1]
		if v >= len(s) || s[v] == '=' || isSpaceByte(s[v]) {
			continue
		}
		c.hideValue(v, lineEnd(s, v))
	}
}

var sqlKeyRx = regexp.MustCompile(`(?i)\b(?:PASSWORD(?:[ \t]+FOR[ \t]+\S+[ \t]*=)?|IDENTIFIED(?:[ \t]+WITH[ \t]+\w+)?[ \t]+BY(?:[ \t]+VALUES)?)\s+`)
var identifiedByRx = regexp.MustCompile(`(?i)\bIDENTIFIED[ \t]+BY[ \t]+`)

func (c *scan) sql() {
	s := c.s
	for _, m := range sqlKeyRx.FindAllStringIndex(s, -1) {
		v := m[1]
		if v >= len(s) {
			continue
		}
		j := v
		if s[j] == 'E' || s[j] == 'e' || s[j] == 'N' || s[j] == 'n' {
			if j+1 < len(s) && s[j+1] == '\'' {
				j++
			}
		}
		switch {
		case s[j] == '\'' || s[j] == '"':
			q := s[j]
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
			if k < len(s) && s[k] == q && k > j+1 {
				c.hideValue(j+1, k)
			}
		case strings.HasPrefix(s[j:], "$$"):
			k := strings.Index(s[j+2:lineEnd(s, j+2)], "$$")
			if k > 0 {
				c.hideValue(j+2, j+2+k)
			}
		}
	}
	for _, m := range identifiedByRx.FindAllStringIndex(s, -1) {
		v := m[1]
		up := strings.ToUpper(s[v:])
		if (strings.HasPrefix(up, "VALUES") && !isWordAt(s, v+6)) || (strings.HasPrefix(up, "PASSWORD") && !isWordAt(s, v+8)) {
			continue
		}
		e := v
		for e < len(s) && !isSpaceByte(s[e]) && strings.IndexByte(";'\"$", s[e]) < 0 {
			e++
		}
		c.hideValue(v, e)
	}
}

var blockHeadRx = regexp.MustCompile(`(?im)^([+-]?)([ \t]*)(?:-[ \t]+)?["']?([A-Za-z0-9_-]+)["']?[ \t]*:[ \t]*(?:[!&]\S*[ \t]+)*[|>][-+0-9]*[ \t]*(?:#[^\r\n]*)?\r?\n`)

// blockScalars: a YAML block scalar under a credential's name: every line after it indented
// deeper than the name's line.
func (c *scan) blockScalars() {
	s := c.s
	for _, h := range blockHeadRx.FindAllStringSubmatchIndex(s, -1) {
		if !IsCredentialName(s[h[6]:h[7]]) {
			continue
		}
		marker := s[h[2]:h[3]]
		pos := h[1]
		following := s[pos:lineEnd(s, pos)]
		if marker != "" && !strings.HasPrefix(following, marker) {
			marker = ""
		}
		line := s[h[0]:h[1]][len(marker):]
		depth := len(line) - len(strings.TrimLeft(line, " \t"))
		end := pos
		for pos < len(s) {
			le := lineEnd(s, pos)
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
		if end > h[1] {
			c.hideValue(h[1], end)
		}
	}
}

func hasWordChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if isWordAt(s, i) {
			return true
		}
	}
	return false
}
