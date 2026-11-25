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
	if codeWordAt(s, i) {
		return true
	}
	if code, decided := codeSigilAt(s, i); decided {
		return code
	}
	if !isIdentStart(s[i]) {
		return false
	}
	j, parts := identChainEnd(s, i)
	k := lex.SkipBlanks(s, j)
	// A bracket after a blank leaves a dotted password a value (`Ab.CDEFgH2 (rotated)`): prose going on, not a call.
	if k < len(s) && (s[k] == '(' || s[k] == '[') && (k == j || parts < 2 || !chainHoldsValuePart(s, i, j)) {
		return true
	}
	return parts > 1 && !nameGoesOnAt(s, j) && !chainHoldsValuePart(s, i, j)
}

// chainHoldsValuePart: a part of the member chain s[i:j] mixes upper case, lower case and a digit, or holds a digit
// between letters (`Ab.CDEFgH2`, `x9.Kq2Lm.Pw7`): the chain is a dotted password, not member access.
func chainHoldsValuePart(s string, i, j int) bool {
	for i < j {
		e := i
		for e < j && memberLen(s, e) == 0 {
			e++
		}
		if valuePart(s[i:e]) {
			return true
		}
		i = e + memberLen(s, e)
	}
	return false
}

// valuePart: the name p mixes upper case, lower case and a digit, or a run of digits stands between two letters.
func valuePart(p string) bool {
	lower, upper, digit := false, false, false
	for k := 0; k < len(p); k++ {
		c := p[k]
		lower = lower || lex.IsLowerASCII(c)
		upper = upper || lex.IsUpperASCII(c)
		digit = digit || lex.IsDigitASCII(c)
		if k > 0 && lex.IsDigitASCII(c) && isASCIILetter(p[k-1]) && letterAfterDigits(p, k) {
			return true
		}
	}
	return lower && upper && digit
}

// letterAfterDigits: the run of digits starting at k is followed by a letter.
func letterAfterDigits(p string, k int) bool {
	for k < len(p) && lex.IsDigitASCII(p[k]) {
		k++
	}
	return k < len(p) && isASCIILetter(p[k])
}

func isASCIILetter(c byte) bool { return lex.IsLowerASCII(c) || lex.IsUpperASCII(c) }

// nameGoesOnAt: a name character or a word stands at j.
func nameGoesOnAt(s string, j int) bool {
	return j < len(s) && (isIdentChar(s[j]) || lex.IsWordAt(s, j))
}

// codeWordAt: a keyword (`null`, `self`) or a leading operator word (`await`, `new`) standing as a whole word at i.
func codeWordAt(s string, i int) bool {
	rest := s[i:]
	if m := codeKeywordRx.FindString(rest); m != "" {
		n := i + len(m)
		if n >= len(s) || !isIdentChar(s[n]) && s[n] != '.' && !lex.IsWordAt(s, n) && !gluedToWord(s, n) {
			return true
		}
	}
	if m := codeLeadRx.FindString(rest); m != "" {
		n := i + len(m)
		if !lex.IsWordAt(s, n) && !gluedToWord(s, n) {
			return true
		}
	}
	return false
}

// gluedToWord: one punctuation byte at n with a word right after it (`Fn-DMLYtO2`, `True@x9`): the code word at
// its start is the head of one token, a credential's value, not a keyword. An operator of two bytes (`this->x`,
// `null??x`, `true&&x`), a bracket (`self[k]`, `not(x)`), a statement's end (`null;next = 1`) or a sed expression's
// delimiter (`s/x = None/y/`) still leaves the word code.
func gluedToWord(s string, n int) bool {
	if n+1 >= len(s) || lex.IsSpaceByte(s[n]) || strings.IndexByte("()[]{};/", s[n]) >= 0 {
		return false
	}
	return lex.IsWordAt(s, n+1)
}

// codeSigilAt: whether a value opening with a query or format sigil (`?`, `$1`, `%s`, `:name`) is code;
// decided false when s[i] is none of them.
func codeSigilAt(s string, i int) (code, decided bool) {
	switch s[i] {
	case '?':
		return !nameGoesOnAt(s, i+1), true
	case '$':
		j := i + 1
		for j < len(s) && lex.IsDigitASCII(s[j]) {
			j++
		}
		// `$1` is a query parameter; `$1$...` is a crypt hash's head, a value.
		return j > i+1 && !lex.IsWordAt(s, j) && (j >= len(s) || s[j] != '$'), true
	case '%':
		return i+1 < len(s) && s[i+1] == 's' && !lex.IsWordAt(s, i+2), true
	case ':':
		return i+1 < len(s) && (lex.IsLowerASCII(s[i+1]) || lex.IsUpperASCII(s[i+1]) || s[i+1] == '_'), true
	}
	return false, false
}

// identChainEnd: the end of the chain of names joined by members (`a.b`, `a::b`, `a->b`, `a?.b`) that starts at i,
// and how many names it holds.
func identChainEnd(s string, i int) (int, int) {
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
	return j, parts
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

// StartsLiteral reports whether the value at i opens a literal, an escaped quote, or a bracket other than a scheme
// tag's (`{SSHA}…`).
func StartsLiteral(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	if strings.IndexByte("\"'`[({\\", s[i]) >= 0 {
		return s[i] != '{' || lex.SchemeTagEnd(s, i) < 0
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

// CodeWordEnd returns where the code word at i ends: `[^\s;,)\]}#"'`\\]+`, past a scheme tag at i or glued later in
// the word (`{SSHA}…`, `y{SSHA}…`), after which a `#` is the password's, not a comment's (`{PLAIN}#pw`). From a crypt hash's head on (`$argon2id$`,
// `argon2$argon2id$`), the word takes its parameters' commas (`m=65536,t=3,p=4`) to a blank, a quote or a backslash,
// its trailing punctuation left. A `#` before a crypt head or a `#{TAG}` later in its word (`ab#$scrypt$…`,
// `#{CRYPT}$6$…`) is the hash's, not a comment.
func CodeWordEnd(s string, i int) int {
	j, stop := i, ";,)]}#\"'`\\"
	if te := lex.SchemeTagEnd(s, i); te > 0 {
		j, stop = te, ";,)]}\"'`\\"
	}
	for j < len(s) && !lex.IsSpaceByte(s[j]) {
		if te := hashTagEnd(s, j); te > 0 {
			j, stop = te, ";,)]}\"'`\\"
			continue
		}
		if te := lex.SchemeTagEnd(s, j); te > 0 {
			j, stop = te, ";,)]}\"'`\\"
			continue
		}
		if strings.IndexByte(stop, s[j]) >= 0 {
			h := hashedHeadAt(s, j)
			if h < 0 {
				break
			}
			j = h
			continue
		}
		if cryptHeadEnd(s, j) > 0 {
			return cryptWordEnd(s, j)
		}
		j++
	}
	return j
}

// hashTagEnd: just past a scheme tag glued to a `#` at j (`#{CRYPT}`), or -1.
func hashTagEnd(s string, j int) int {
	if s[j] != '#' {
		return -1
	}
	return lex.SchemeTagEnd(s, j+1)
}

// hashedHeadAt: for a `#` at j, where the crypt head (`#$scrypt$`, `x#y$argon2id$`) or the scheme tag (`a#b#{PLAIN}pw`,
// `x#y{SSHA}…`) that makes it the hash's stands later in its word, or -1. The word runs to a blank or a stop.
func hashedHeadAt(s string, j int) int {
	if s[j] != '#' {
		return -1
	}
	for k := j + 1; k < len(s) && !lex.IsSpaceByte(s[k]) && strings.IndexByte(";,)]}\"'`\\", s[k]) < 0; k++ {
		switch {
		case s[k] == '$':
			if cryptHeadEnd(s, k) > 0 {
				return k
			}
			return -1
		case hashTagEnd(s, k) > 0, lex.SchemeTagEnd(s, k) > 0:
			return k
		}
	}
	return -1
}

// cryptHeadEnd: just past a crypt hash's head at i (`$2b$`, `$argon2id$`, `$bcrypt-sha256$`), or -1.
func cryptHeadEnd(s string, i int) int {
	if i+1 >= len(s) || s[i] != '$' || !lex.IsAlnumASCII(s[i+1]) {
		return -1
	}
	j := i + 2
	for j < len(s) && (lex.IsAlnumASCII(s[j]) || s[j] == '_' || s[j] == '-') {
		j++
	}
	if j >= len(s) || s[j] != '$' {
		return -1
	}
	return j + 1
}

// cryptWordEnd: where the crypt hash at i ends: a blank, a quote or a backslash, less any `,` `;` `)` `]` `}` before it.
func cryptWordEnd(s string, i int) int {
	j := i
	for j < len(s) && !lex.IsSpaceByte(s[j]) && strings.IndexByte("\"'`\\", s[j]) < 0 {
		j++
	}
	for j > i && strings.IndexByte(",;)]}", s[j-1]) >= 0 {
		j--
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
		op, ok := lex.LiteralOpen(s, pos, end)
		if !ok {
			return
		}
		st, open, slashes, quote := op.Start, op.Open, op.Slashes, op.Quote
		var stop bool
		if enclosing, stop = enclosingQuote(enclosing, slashes, quote); stop {
			return
		}
		cl, closing := c.literalClose(open, slashes, quote, end, hard)
		bodyEnd := cl - len(closing)
		if literalBodyGoes(s, open, bodyEnd, closing, st == prevEnd) {
			c.hideLiteral(st, open, bodyEnd, cl, closing)
		}
		prevEnd = closedEnd(cl, closing)
		if pos, stop = c.literalResume(open, bodyEnd, cl, end, closing); stop {
			return
		}
	}
}

// enclosingQuote: the quote of the escaped literal the statement's literals sit inside (the first escaped one
// sets it); stop when an unescaped literal in that quote opens, which is the enclosing literal closing.
func enclosingQuote(enclosing, slashes, quote string) (string, bool) {
	if enclosing != "" && slashes == "" && quote == enclosing {
		return enclosing, true
	}
	if enclosing == "" && slashes != "" {
		enclosing = quote
	}
	return enclosing, false
}

// literalClose: where the literal opening at open closes and its closing quote ("" when unclosed); with hard,
// a literal reading past end is cut there as unclosed.
func (c *Scan) literalClose(open int, slashes, quote string, end int, hard bool) (int, string) {
	cl, closing := lex.LiteralEnd(c.S, open, slashes, quote, end)
	if hard && cl > end {
		cl, closing = end, ""
	}
	return cl, closing
}

// literalBodyGoes: whether the literal's body (open to bodyEnd) is a value to hide.
func literalBodyGoes(s string, open, bodyEnd int, closing string, gluedToPrev bool) bool {
	// An unclosed literal of punctuation that closes brackets, opening right where the
	// previous literal closed (`'x'],` read with its closing quote as an opener), is the
	// statement's end, not a value. Any other unclosed literal's body goes.
	return bodyEnd > open && strings.TrimSpace(s[open:bodyEnd]) != "" &&
		(closing != "" || hasWordChar(s[open:bodyEnd]) || !strings.ContainsAny(s[open:bodyEnd], ")]}") || !gluedToPrev)
}

// hideLiteral hides a literal's body and records the literal under the scan's rule.
func (c *Scan) hideLiteral(st, open, bodyEnd, cl int, closing string) {
	if closing != "" {
		// A closed literal is one value to its closing quote: a placeholder and more words
		// in it is a value partly sent.
		c.hideWords(open, bodyEnd)
	} else {
		c.hideValue(open, bodyEnd)
	}
	c.lits[c.litRule] = append(c.lits[c.litRule], litSpan{st, cl, open - st, closing})
}

// closedEnd: where a closed literal ends, or -1 for an unclosed one.
func closedEnd(cl int, closing string) int {
	if closing != "" {
		return cl
	}
	return -1
}

// literalResume: where the next literal is looked for after this one: past it, or at its opening when it is
// unclosed and its body is only a placeholder; stop when an unclosed literal ended at its opening (nothing read)
// at or past the statement's end.
func (c *Scan) literalResume(open, bodyEnd, cl, end int, closing string) (int, bool) {
	if cl <= open {
		cl = open
	}
	pos := cl
	// An unclosed literal whose body is a placeholder already written paired a quote
	// wrongly: the statement's later literals are read on their own.
	if closing == "" && bodyEnd > open && HeldOnlyAt(c.S, open, bodyEnd) {
		return open, false
	}
	if pos == open && closing == "" && cl >= end {
		return pos, true
	}
	return pos, false
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
