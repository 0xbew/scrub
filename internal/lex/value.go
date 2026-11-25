package lex

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxValueChars: how much of a value, outside its literals, is read for a stop before the statement's end (in its
// window) is taken instead.
const maxValueChars = 500

// statementWindow: how far past a value's start its statement is looked for: each name's value is read on its own, so
// a statement read from the line's start made a line of many names quadratic. A literal that crosses it is read to
// its close.
const statementWindow = maxValueChars + maxLiteralChars

// maxLiteralChars: the longest literal the literal rules read.
const maxLiteralChars = 4000

// maxLiteralLines: how many next lines that open with a literal a value is read on over.
const maxLiteralLines = 12

// ColonValue returns the value [v, end) after a credential's name s[start:e] and its colon, where the value's literals
// are read whatever the value opens with (a type, a code span, a call): the name unquoted, first on its line or after
// `{` `,` `(`, maybe owned (`db.password:`); or the name quoted (`"password":`, `\"token\":`) and not compared
// (`k == "password":`). An unquoted name's value that is one word or placeholder ending its line is the whole value
// (a diff's next `+` row does not go on with it), and a block scalar's body is another rule's. ok is false for any
// other colon.
// statementEnd gives where the statement holding a position ends.
func ColonValue(s string, start, e int, statementEnd func(string, int) int) (v, end int, ok bool) {
	v, ok = colonValueHead(s, start, e)
	if !ok || blockIndicatorAt(s, v) {
		return 0, 0, false
	}
	return v, boundedValueEnd(s, start, v, statementEnd), true
}

// KeywordCallValue returns the value [v, end) after a credential's name s[start:e] and an `=` glued to it (perhaps
// quoted or indexed: `["token"]=`): a keyword argument, after `(` or `,`, whatever its value opens with
// (`f(password=pw or "…")`) and perhaps on the next line; or anywhere when the value is a call, an index or a lambda
// (`password=os.environ.get("PW", "…")`, `token=lambda a, b: "…"`), on the same line or after a continuation. A
// shell's `NAME=$(cmd)` opens no call, so only an argument's reads. ok is false for a comparison or any other `=`.
// statementEnd gives where the statement holding a position ends.
func KeywordCallValue(s string, start, e int, statementEnd func(string, int) int) (v, end int, ok bool) {
	v, ok = keywordCallHead(s, start, e)
	if !ok {
		return 0, 0, false
	}
	return v, boundedValueEnd(s, start, v, statementEnd), true
}

// keywordCallHead: where the value starts after the name s[start:e] and a glued `=`, when the name is an argument or
// the value is a call, an index or a lambda.
func keywordCallHead(s string, start, e int) (v int, ok bool) {
	k := e
	for k < len(s) && s[k] == '\\' {
		k++
	}
	if k < len(s) && (s[k] == '"' || s[k] == '\'') {
		k++
	} else {
		k = e
	}
	if k < len(s) && s[k] == ']' {
		k++
	}
	if k >= len(s) || s[k] != '=' || k+1 < len(s) && strings.IndexByte("=~>", s[k+1]) >= 0 {
		return 0, false
	}
	// An empty assignment ending its line (`API_KEY=`) does not take the next statement as its value.
	arg := argumentAt(s, start)
	v = k + 1
	if n := nextLineIndentAfter(s, v); n > v && (arg || s[v] == '\\') {
		v = n
	}
	return v, arg || codeCallAt(s, v)
}

// argumentAt: the name at start is a call's argument: after `(` or `,`, perhaps on a line of its own.
func argumentAt(s string, start int) bool {
	j := start
	for j > 0 && IsSpaceByte(s[j-1]) {
		j--
	}
	return j > 0 && (s[j-1] == '(' || s[j-1] == ',')
}

// nextLineIndentAfter: past a line break at i (perhaps after a continuation's `\`) and the next line's indent; i when
// none is there.
func nextLineIndentAfter(s string, i int) int {
	k := i
	if k < len(s) && s[k] == '\\' {
		k++
	}
	if k < len(s) && s[k] == '\r' {
		k++
	}
	if k >= len(s) || s[k] != '\n' {
		return i
	}
	return SkipBlanks(s, k+1)
}

// codeCallAt: a `lambda`, or a dotted name then `(` or `[`, at v.
func codeCallAt(s string, v int) bool {
	if strings.HasPrefix(s[v:], "lambda") && !IsWordAt(s, v+len("lambda")) {
		return true
	}
	if v >= len(s) || !IsLowerASCII(s[v]) && !IsUpperASCII(s[v]) && s[v] != '_' {
		return false
	}
	k := v + 1
	for k < len(s) && (IsAlnumASCII(s[k]) || s[k] == '_' || s[k] == '.') {
		k++
	}
	return k < len(s) && (s[k] == '(' || s[k] == '[')
}

// boundedValueEnd: where the value at v after the name at start ends (colonValueEnd), its statement read from the
// name over a bounded window: from its line's start, every name of a long line read the whole line.
func boundedValueEnd(s string, start, v int, statementEnd func(string, int) int) int {
	w := s[start:min(len(s), v+statementWindow)]
	return colonValueEnd(s, v, start+valueStatementEnd(w, statementEnd))
}

// valueStatementEnd: where the statement at w's start ends, read on over each next line that opens with a literal
// that is no key (`password: foo` then `"…"`), up to maxLiteralLines of them: the value still ends at its own `,` or
// bracket.
func valueStatementEnd(w string, statementEnd func(string, int) int) int {
	end := statementEnd(w, 0)
	for n := 0; n < maxLiteralLines && end < len(w) && literalLineAt(w, end+1); n++ {
		end = statementEnd(w, end+1)
	}
	return end
}

// literalLineAt: the line at i opens with a literal, perhaps after blanks and a prefix (`f"…"`), that is no key and no
// triple quote: a key (`"name": x`) starts a field of its own, so a YAML or JSON line after a lone word stays its own,
// and a triple quote as often closes the string the lines sit in.
func literalLineAt(s string, i int) bool {
	k := skipLineSpace(s, i)
	for n := 0; n < 2 && k < len(s) && strings.IndexByte("rRbBuUfFnNeE", s[k]) >= 0; n++ {
		k++
	}
	if k >= len(s) || s[k] != '"' && s[k] != '\'' && s[k] != '`' {
		return false
	}
	if k+2 < len(s) && s[k+1] == s[k] && s[k+2] == s[k] {
		return false
	}
	e := lineLiteralEnd(s, k)
	if e < 0 {
		return true
	}
	e = SkipBlanks(s, e)
	return e >= len(s) || s[e] != ':'
}

// skipLineSpace: past the white space at i other than a line break, a form feed, a no-break space or another Unicode
// space included: a line indented with one opens with what follows it.
func skipLineSpace(s string, i int) int {
	for i < len(s) {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == '\n' || r == '\r' || !unicode.IsSpace(r) {
			return i
		}
		i += n
	}
	return i
}

// lineLiteralEnd: past the literal whose quote is at k when it closes on its line, else -1. In a `"` or `'` literal a
// backslash escapes the next character other than a line break.
func lineLiteralEnd(s string, k int) int {
	q := s[k]
	for j := k + 1; j < len(s) && s[j] != '\n'; j++ {
		switch {
		case s[j] == '\\' && q != '`':
			if j+1 < len(s) && s[j+1] == '\n' {
				return -1
			}
			j++
		case s[j] == q:
			return j + 1
		}
	}
	return -1
}

// blockIndicatorAt: a YAML block scalar's `|` or `>` at v ends its line (`key: |-`, `key: > # note`).
func blockIndicatorAt(s string, v int) bool {
	if v >= len(s) || s[v] != '|' && s[v] != '>' {
		return false
	}
	k := v + 1
	for k < len(s) && (s[k] == '-' || s[k] == '+' || IsDigitASCII(s[k])) {
		k++
	}
	k = SkipBlanks(s, k)
	if k < len(s) && s[k] == '#' {
		k = LineEnd(s, k)
	}
	return k >= len(s) || s[k] == '\n' || s[k] == '\r'
}

// colonValueHead: where the value starts after the name s[start:e] and its colon, when ColonValue reads it.
func colonValueHead(s string, start, e int) (v int, ok bool) {
	k := e
	for k < len(s) && s[k] == '\\' {
		k++
	}
	quoted := k < len(s) && (s[k] == '"' || s[k] == '\'')
	if quoted {
		k++
	} else if k > e {
		return 0, false
	}
	k = SkipBlanks(s, k)
	if k >= len(s) || s[k] != ':' || k+1 < len(s) && strings.IndexByte(":=/", s[k+1]) >= 0 {
		return 0, false
	}
	v = SkipBlanks(s, k+1)
	if quoted {
		return v, !comparedBefore(s, start)
	}
	return v, unquotedHeadContext(s, start) && !LoneWordEndsLine(s, v)
}

// comparedBefore: the quoted name at start is compared, not a key (`if k == "password":`, `!= 'token'`).
func comparedBefore(s string, start int) bool {
	j := start
	for j > 0 && (s[j-1] == '\\' || s[j-1] == '"' || s[j-1] == '\'') {
		j--
	}
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return j >= 2 && s[j-1] == '=' && (s[j-2] == '=' || s[j-2] == '!')
}

// unquotedHeadContext: before the name at start, its dotted owners, then blanks, diff markers or a list dash, from
// the line's start or a `{` `,` `(`.
func unquotedHeadContext(s string, start int) bool {
	j := start
	for j > 0 && s[j-1] == '.' {
		k := j - 1
		for k > 0 && (IsAlnumASCII(s[k-1]) || s[k-1] == '_' || s[k-1] == '$') {
			k--
		}
		if k == j-1 {
			return false
		}
		j = k
	}
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '+' || s[j-1] == '-') {
		j--
	}
	return j == 0 || strings.IndexByte("\n{,(", s[j-1]) >= 0
}

// LoneWordEndsLine reports whether the value at v is one word (letters, digits, `_` `$` `.`) or placeholder, then perhaps a comment,
// ending its line, and the next line does not go on with an indented operator or open with a literal that is no key.
func LoneWordEndsLine(s string, v int) bool {
	k := v
	if n := PlaceholderAt(s, v); n > 0 {
		k += n
	} else {
		for k < len(s) && (IsWordAt(s, k) || s[k] == '$' || s[k] == '.') {
			k++
		}
	}
	if k == v {
		return false
	}
	k = SkipBlanks(s, k)
	if k < len(s) && s[k] == '#' {
		k = LineEnd(s, k)
	}
	if k < len(s) && s[k] == '\r' {
		k++
	}
	if k >= len(s) {
		return true
	}
	return s[k] == '\n' && !operatorLineAt(s, k+1) && !literalLineAt(s, k+1)
}

// operatorLineAt: the line at i is indented and opens with an operator that goes on with the line before
// (`    ?? "x"`, `  + "x"`, `  or "x"`).
func operatorLineAt(s string, i int) bool {
	k := SkipBlanks(s, i)
	if k == i || k >= len(s) {
		return false
	}
	if strings.IndexByte(".[(%+*|&?!", s[k]) >= 0 {
		return true
	}
	for _, w := range []string{"if", "or", "and"} {
		if strings.HasPrefix(s[k:], w) && !IsWordAt(s, k+len(w)) {
			return true
		}
	}
	return false
}

// colonValueEnd: where the value starting at pos ends, at most at end (its statement's end): at the first `,` outside
// brackets, literals and a lambda's parameters (`lambda a, b: "x"`), or at a bracket closing one opened before pos,
// or a quote closing a string the value sits in. A `;` does not end it: the literals after one are read to the
// statement's end (`{"password": str;"…"}`), as an assignment's are. maxValueChars read outside literals without one,
// it is end: a long literal is skipped whole and does not count.
func colonValueEnd(s string, pos, end int) int {
	depth, params, read, i := 0, 0, 0, pos
	for ; i < end; read++ {
		if read > maxValueChars {
			return end
		}
		c := s[i]
		switch {
		case (c == '"' || c == '\'') && closesString(s, pos, i):
			return i
		case c == '"' || c == '\'' || c == '`' || c == '\\':
			i = valueLiteralEnd(s, i, end)
			continue
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth == 0 {
				return i
			}
			depth--
		case depth > 0:
		case c == ':' && params > 0:
			params--
		case c == ',' && params == 0:
			return i
		case c == 'l' && strings.HasPrefix(s[i:], "lambda") && !WordBefore(s, i) && !IsWordAt(s, i+len("lambda")):
			params++
		}
		i++
	}
	// A literal that crosses end is the value's to its close.
	return max(i, end)
}

// closesString: the quote at i opens no literal that closes on its line, and the value at pos sits inside a string
// that quote opened before it (`'"otp": "1"'`): it ends that string, and the value with it. The line before pos is
// read back at most maxValueChars; a longer one reads as no enclosing string, so the quote opens a literal.
func closesString(s string, pos, i int) bool {
	e := objectStringEnd(s, i, s[i])
	if e > i+1 && s[e-1] == s[i] {
		return false
	}
	ls := max(0, pos-maxValueChars)
	if k := strings.LastIndexByte(s[ls:pos], '\n'); k >= 0 {
		ls += k + 1
	} else if ls > 0 {
		return false
	}
	return strings.Count(s[ls:pos], s[i:i+1])%2 == 1
}

// valueLiteralEnd: past the literal whose quote (perhaps after backslashes) is at i, as LiteralOpen and LiteralEnd read
// it, so the value ends where the literals the scrubber hides and the audit reads end; or past the backslashes when no
// quote follows them.
func valueLiteralEnd(s string, i, end int) int {
	q := i
	for q < end && s[q] == '\\' {
		q++
	}
	if q >= end || s[q] != '"' && s[q] != '\'' && s[q] != '`' {
		return max(q, i+1)
	}
	op, _ := LiteralOpen(s, i, q+1)
	cl, _ := LiteralEnd(s, op.Open, op.Slashes, op.Quote, end)
	return max(cl, op.Open)
}
