package scrub

import (
	"regexp"
	"strings"
)

// Kind is what a hidden span becomes when it is rendered.
type Kind uint8

const (
	KindSecret Kind = iota
	KindLong
	KindJWT
	KindEmail
	KindPhone
	KindOwner
	KindTeammate
	KindPerson
	KindVendor
)

// Span is a hidden range of the source text, in byte offsets.
type Span struct {
	Lo, Hi int
	Kind   Kind
}

type spanSet struct{ spans []Span }

func (o *spanSet) add(lo, hi int, k Kind) {
	if lo < hi {
		o.spans = append(o.spans, Span{lo, hi, k})
	}
}

// scan runs the detectors over one reading.
type scan struct {
	s   string
	r   *reading
	out *spanSet
	// lits: the statement literals each credential's reading found, per rule, merged across
	// readings at the end of code() (litMerge).
	lits    [2][]litSpan
	litRule int
}

func (c *scan) hide(a, b int, k Kind) {
	if a < 0 {
		a = 0
	}
	if b > len(c.s) {
		b = len(c.s)
	}
	if a >= b {
		return
	}
	lo, hi := c.r.source(a, b)
	c.out.add(lo, hi, k)
}

// sourceText: the source text a reading span came from (an encoded value as written).
func (c *scan) sourceText(a, b int) string {
	lo, hi := c.r.source(a, b)
	if c.r.src == "" || hi > len(c.r.src) {
		return c.s[a:b]
	}
	return c.r.src[lo:hi]
}

// hideValue hides s[a:b] unless it is already entirely placeholders.
func (c *scan) hideValue(a, b int) {
	if a >= b || (onlyPlaceholders(c.s[a:b]) || heldOnlyAt(c.s, a, b)) && !otherKindPlaceholder(c.s[a:b]) {
		return
	}
	c.hide(a, b, KindSecret)
}

// contLineEnd: the end of the line at i, read on past each continuation (`\` then a line
// break), before a trailing carriage return.
func contLineEnd(s string, i int) int {
	for {
		le := lineEnd(s, i)
		if le < len(s) && le > i && s[le-1] == '\\' && !escapedAt(s, le-1) {
			i = le + 1
			continue
		}
		if le >= 2 && le < len(s) && s[le-1] == '\r' && s[le-2] == '\\' && !escapedAt(s, le-2) {
			i = le + 1
			continue
		}
		if le > i && s[le-1] == '\r' {
			le--
		}
		return le
	}
}

// hideWords hides s[a:b], a value read to a closing quote or a stop word, unless it is
// entirely placeholders: a placeholder and more words is a value partly sent.
func (c *scan) hideWords(a, b int) {
	if a < b && (!onlyPlaceholders(c.s[a:b]) || otherKindPlaceholder(c.s[a:b])) {
		c.hide(a, b, KindSecret)
	}
}

// otherKindPlaceholder: a credential's value holding another kind's placeholder (`[email]`, `<redacted> [phone]`):
// only a secret's placeholder stands for a hidden value, so a receiver reads the other as the value left, and the
// value goes whole.
func otherKindPlaceholder(v string) bool {
	for i := strings.IndexByte(v, '['); i >= 0; i = nextByte(v, '[', i+1) {
		if placeholderAt(v, i) > 0 {
			return true
		}
	}
	return false
}

// heldOnly: a value that is a placeholder already written, then a quote and what is glued
// on, holding nothing but placeholders and quotes: scrubbed text, read again. A quote after
// the placeholder that closes one opened earlier on its line ends the value; one that opens
// a part takes that part into it (`password=<redacted>"hunter2"` is a value left).
func heldOnly(v string) bool { return heldOnlyAt(v, 0, len(v)) }

func heldOnlyAt(s string, a, b int) bool {
	n := placeholderAt(s, a)
	if n == 0 {
		return false
	}
	end := a + n
	q := end
	for q < b && s[q] == '\\' {
		q++
	}
	if q >= b || (s[q] != '"' && s[q] != '\'') {
		return end == b || (end < b && isGluedBreak(s[end]))
	}
	quote := s[end : q+1]
	start := end
	if closesOnLine(s, end, quote) {
		start = q + 1
	}
	at := start
	for at < b {
		e := gluedPartEnd(s, at, b)
		if e == at {
			break
		}
		at = e
	}
	for i := start; i < at; {
		if m := placeholderAt(s, i); m > 0 {
			i += m
			continue
		}
		if s[i] == '"' || s[i] == '\'' || s[i] == '\\' {
			i++
			continue
		}
		return false
	}
	return true
}

func isGluedBreak(c byte) bool { return isSpaceByte(c) || strings.IndexByte(")]},;|&>`", c) >= 0 }

// closesOnLine: an odd number of `quote` (unescaped) before end on its line.
func closesOnLine(s string, end int, quote string) bool {
	ls := lineStart(s, end)
	if end-ls > 4096 {
		return false
	}
	n := 0
	for i := ls; i+len(quote) <= end; i++ {
		if s[i:i+len(quote)] == quote && (i == 0 || s[i-1] != '\\') {
			n++
			i += len(quote) - 1
		}
	}
	return n%2 == 1
}

// gluedPartEnd: one part of a shell word at i: a placeholder, a quoted part (raw or escaped,
// to its closing quote or the line end), or a run up to a word break.
func gluedPartEnd(s string, i, b int) int {
	if n := placeholderAt(s, i); n > 0 {
		return i + n
	}
	j := i
	for j < b && s[j] == '\\' {
		j++
	}
	if j < b && (s[j] == '"' || s[j] == '\'') {
		q := s[j]
		k := j + 1
		for k < b && s[k] != '\n' {
			if q == '"' && s[k] == '\\' && k+1 < b && j == i {
				k += 2
				continue
			}
			if s[k] == q {
				return k + 1
			}
			k++
		}
		return k
	}
	j = i
	for j < b && !isGluedBreak(s[j]) && s[j] != '"' && s[j] != '\'' {
		if s[j] == '\\' {
			k := j
			for k < b && s[k] == '\\' {
				k++
			}
			if k < b && (s[k] == '"' || s[k] == '\'') {
				break
			}
			j = k
			continue
		}
		j++
	}
	return j
}

// extendEncoded: an encoded value as written runs on over the characters the decoded
// reading split it at (`abc+rest`), to a space, a quote or an encoded space or quote.
func (c *scan) extendEncoded(a, b int) {
	src := c.r.src
	if src == "" || a >= b {
		return
	}
	lo, hi := c.r.source(a, b)
	if hi > len(src) {
		return
	}
	v := src[lo:hi]
	if strings.HasPrefix(v, "%22") || strings.HasPrefix(v, "%27") || strings.HasPrefix(v, "\"") || strings.HasPrefix(v, "'") {
		return
	}
	e := hi
	for e < len(src) && !isSpaceByte(src[e]) && src[e] != '"' && src[e] != '\'' {
		if src[e] == '%' && e+2 < len(src) {
			code := strings.ToUpper(src[e+1 : e+3])
			if code == "20" || code == "22" || code == "27" || code == "0A" || code == "0D" {
				break
			}
		}
		e++
	}
	if e > hi && !heldOnly(src[lo:e]) {
		c.out.add(lo, e, KindSecret)
	}
}

// hideQuotedBody hides a value, keeping a closed pair of quotes around it.
func (c *scan) hideQuotedBody(a, b int) {
	v := c.s[a:b]
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'' || v[0] == '`') && v[len(v)-1] == v[0] {
		c.hideValue(a+1, b-1)
		return
	}
	if len(v) >= 1 && (v[0] == '"' || v[0] == '\'') {
		c.hideValue(a+1, b)
		return
	}
	c.hideValue(a, b)
}

// --- the keyword precondition -----------------------------------------------------------

// keywordRx: a name run holding one of these is a candidate a random-looking value is judged
// under. A credential's name always holds one.
var keywordRx = regexp.MustCompile(`(?i)(?:key|token|secret|pass|passwd|password|pwd|dsn|credentials?|auth|pin|otp|mfa|2fa|(?:` +
	strings.Join(CodeOwners, "|") + `)[_-]?code)`)
var patRx = regexp.MustCompile(`(?i)pat`)

func hasKeyword(name string) bool {
	if keywordRx.MatchString(name) {
		return true
	}
	for _, m := range patRx.FindAllStringIndex(name, -1) {
		if m[1] >= len(name) || !(isLowerASCII(name[m[1]]) || isUpperASCII(name[m[1]])) {
			return true
		}
	}
	return false
}

// judged: whether a name's value is hidden: a credential's always; any other candidate's
// when the value, or its first word, looks random.
func judged(name, value string) bool {
	if IsCredentialName(name) {
		return true
	}
	if !hasKeyword(name) {
		return false
	}
	if LooksSecret(value) {
		return true
	}
	if f := strings.Fields(value); len(f) > 0 && LooksSecret(f[0]) {
		return true
	}
	return false
}

// --- R1: named values --------------------------------------------------------------------

// named: `NAME=value`, a quoted `"NAME"=value`, every `=` read on its own.
func (c *scan) named() {
	if off("named") {
		return
	}
	s := c.s
	outerEnd, depth := 0, 0
	for p := strings.IndexByte(s, '='); p >= 0; p = nextByte(s, '=', p+1) {
		vs := p + 1
		q := nameRunBefore(s, p)
		var name string
		if q < p {
			name = trimDashes(s[q:p])
		} else if p > 0 && (s[p-1] == ' ' || s[p-1] == '\t') {
			c.spacedKeywordAssignment(p)
			continue
		} else if p > 0 && (s[p-1] == '"' || s[p-1] == '\'') {
			// A quoted name before `=`: `"DB_PASSWORD"=x`, `\"token\"=x`.
			e := p - 1
			for e > 0 && s[e-1] == '\\' {
				e--
			}
			q2 := nameRunBefore(s, e)
			if q2 == e || q2 == 0 || s[q2-1] != s[p-1] {
				continue
			}
			name = trimDashes(s[q2:e])
			if !IsCredentialName(name) {
				continue
			}
			ve := valueEnd(s, vs)
			c.hideValue(vs, ve)
			continue
		} else {
			continue
		}
		if name == "" || !(isAlnumASCII(name[0]) || name[0] == '_') {
			continue
		}
		ve := valueEnd(s, vs)
		if ve == vs {
			c.nextLineValue(name, vs)
			continue
		}
		if hasKeyword(name) {
			// Assignments nested in one value are followed this deep; past it the value goes.
			if q < outerEnd {
				depth++
			} else {
				depth = 0
			}
			if ve > outerEnd {
				outerEnd = ve
			}
		}
		if judged(name, s[vs:ve]) || (c.r.pctd && judged(name, c.sourceText(vs, ve))) || depth >= maxNestedAssignments {
			c.hideValue(vs, ve)
			if c.r.pctd {
				c.extendEncoded(vs, ve)
			}
		}
	}
}

// heredocValues: each heredoc that opens a credential's value after its name and `=` or `:` (`DB_PASSWORD=<<EOF`,
// `token: <<EOF`, mid-line or not), its body's span: the scrubber hides it and the audit refuses it live, so the two
// read the same shape. One opener a line is read, so a long line of openers stays linear.
func heredocValues(s string, emit func(lo, hi int)) {
	lineDone := -1
	for p := strings.IndexAny(s, "=:"); p >= 0; {
		if p >= lineDone {
			if v := skipBlanks(s, p+1); strings.HasPrefix(s[v:], "<<") && !strings.HasPrefix(s[v:], "<<<") {
				e := p
				for e > 0 && (s[e-1] == ' ' || s[e-1] == '\t') {
					e--
				}
				if q := nameRunBefore(s, e); q < e && IsCredentialName(trimDashes(s[q:e])) {
					lineDone = lineEnd(s, v)
					if lo, hi, ok := heredocBodyAt(s, v); ok {
						emit(lo, hi)
					}
				}
			}
		}
		k := strings.IndexAny(s[p+1:], "=:")
		if k < 0 {
			return
		}
		p += 1 + k
	}
}

// heredocBodyAt: the body of a heredoc whose opener (`<<EOF`, `<<-'END'`) is at i: from the next line to the line
// that is its word alone (a diff row's marker aside), or to the end of the text when none is, as a cut command
// leaves it; never past heredocMaxLines lines.
func heredocBodyAt(s string, i int) (lo, hi int, ok bool) {
	j := i + 2
	if j < len(s) && (s[j] == '-' || s[j] == '~') {
		j++
	}
	var quote byte
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		quote = s[j]
		j++
	}
	w := j
	for j < len(s) && isWordAt(s, j) {
		j++
	}
	if j == w {
		return 0, 0, false
	}
	word := s[w:j]
	if quote != 0 && (j >= len(s) || s[j] != quote) {
		return 0, 0, false
	}
	le := lineEnd(s, j)
	// An escaped line break after the opener is the escaped heredoc (JSON), read as its own reading.
	if strings.Contains(s[j:le], `\n`) || le >= len(s) {
		return 0, 0, false
	}
	lo = le + 1
	k := lo
	for n := 0; n < heredocMaxLines && k < len(s); n++ {
		e := lineEnd(s, k)
		line := strings.TrimSpace(strings.TrimRight(s[k:e], "\r"))
		if line == word || len(line) > 1 && strings.IndexByte("+- ", s[k]) >= 0 && strings.TrimSpace(s[k+1:e]) == word {
			if k > lo {
				// The last body line's break (and its carriage return) stays with the terminator.
				hi = k - 1
				if hi > lo && s[hi-1] == '\r' {
					hi--
				}
				return lo, hi, true
			}
			return lo, lo, true
		}
		if e >= len(s) {
			return lo, len(s), true
		}
		k = e + 1
	}
	return lo, k, true
}

// heredocMaxLines: a heredoc body is read this many lines at most.
const heredocMaxLines = 2000

// nextLineValue: a credential's empty assignment ending its line (`TOKEN=`) and a quoted string opening the next
// one: a receiver may read the string as the value, so its body goes.
func (c *scan) nextLineValue(name string, vs int) {
	s := c.s
	if !IsCredentialName(name) {
		return
	}
	j := vs
	if j < len(s) && s[j] == '\r' {
		j++
	}
	if j >= len(s) || s[j] != '\n' {
		return
	}
	j = skipBlanks(s, j+1)
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		c.hideQuotedBody(j, valueEnd(s, j))
	}
}

// spacedKeywordAssignment: `name = value` with blanks around the `=`, for a keyword name that is not a
// credential's (a credential's is the code detector's), whose value looks random (`airtable_key = k6hn7qed88vb`).
func (c *scan) spacedKeywordAssignment(p int) {
	s := c.s
	if p+1 >= len(s) || (s[p+1] != ' ' && s[p+1] != '\t') {
		return
	}
	e := p
	for e > 0 && (s[e-1] == ' ' || s[e-1] == '\t') {
		e--
	}
	q := nameRunBefore(s, e)
	if q == e || (q > 0 && strings.IndexByte("=!<>", s[q-1]) >= 0) {
		return
	}
	name := trimDashes(s[q:e])
	if name == "" || IsCredentialName(name) || !hasKeyword(name) {
		return
	}
	v := skipBlanks(s, p+1)
	ve := v
	for ve < len(s) && (isAlnumASCII(s[ve]) || strings.IndexByte("-_+/=.~", s[ve]) >= 0) {
		ve++
	}
	for ve > v && strings.IndexByte(".,;:!?)]}", s[ve-1]) >= 0 {
		ve--
	}
	// The word must end there: a quote or a bracket glued on makes it code.
	if ve < len(s) && !isSpaceByte(s[ve]) && strings.IndexByte(".,;:!?)]}\"'`", s[ve]) < 0 {
		return
	}
	if ve > v && judged(name, s[v:ve]) {
		c.hideValue(v, ve)
	}
}

// maxNestedAssignments: `key=key=...` is read this deep before its value is redacted.
const maxNestedAssignments = 20

func nextByte(s string, b byte, from int) int {
	if from >= len(s) {
		return -1
	}
	if k := strings.IndexByte(s[from:], b); k >= 0 {
		return from + k
	}
	return -1
}

// colonStop: what ends a several-word value: a comment, a default, a flag, or what closes
// the field.
func colonStop(s string, i int) bool {
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

// isTypeWord: a type annotation's word at i (`token: str`).
func isTypeWord(s string, i int) bool {
	for _, w := range typeWords {
		if len(s)-i >= len(w) && strings.EqualFold(s[i:i+len(w)], w) && !isWordAt(s, i+len(w)) {
			return true
		}
	}
	return false
}

// isBlockIndicator: a YAML block scalar's `|` or `>` ends the line (`key: |`).
func isBlockIndicator(s string, i int) bool {
	j := i
	for j < len(s) && (s[j] == '!' || s[j] == '&') {
		for j < len(s) && !isSpaceByte(s[j]) {
			j++
		}
		k := skipBlanks(s, j)
		if k == j {
			return false
		}
		j = k
	}
	if j >= len(s) || (s[j] != '|' && s[j] != '>') {
		return false
	}
	j++
	for j < len(s) && (s[j] == '-' || s[j] == '+' || isDigitASCII(s[j])) {
		j++
	}
	j = skipBlanks(s, j)
	if j < len(s) && s[j] == '#' {
		j = lineEnd(s, j)
	}
	if j < len(s) && s[j] == '\r' {
		j++
	}
	return j >= len(s) || s[j] == '\n'
}

// colonContext: where a `name: value` may stand: first on its line (after blanks, a diff
// marker or a list dash), or after `{` or `,`.
func colonContext(s string, q int) (lineHead, flow, flowTight bool) {
	ls := lineStart(s, q)
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
	if n == 0 || (k > ls && !(isSpaceByte(s[k-1]) || strings.IndexByte("=([,", s[k-1]) >= 0)) {
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
			return valueEndFlow(s, j)
		}
		return valueEnd(s, j)
	}
	end := next(i)
	if end == i {
		return i
	}
	for {
		if flow && strings.IndexByte(",;}]", s[end-1]) >= 0 {
			return end
		}
		j := skipBlanks(s, end)
		if j == end || j >= len(s) || colonStop(s, j) {
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
func (c *scan) colon() {
	if off("colon") {
		return
	}
	s := c.s
	for p := strings.IndexByte(s, ':'); p >= 0; p = nextByte(s, ':', p+1) {
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
		q := nameRunBefore(s, qe)
		if q == qe {
			// JSON with a line break or continuation before the colon.
			if jq, je, ok := c.quotedNameBeforeColon(p); ok {
				c.jsonField(jq, je, p)
			}
			continue
		}
		name := trimDashes(s[q:qe])
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
		if ls := lineStart(s, q); lineHead && !flow && !tight && strings.Trim(s[ls:q], " \t+-") != "" {
			if cl := quotedHeadCloser(s, ls, q); cl != "" {
				v := skipBlanks(s, p+1)
				k := closerIndex(s[p+1:contLineEnd(s, p)], cl)
				if v == p+1 || k < 0 || p+1+k <= v || s[v] == '$' || s[v] == '{' || isTypeWord(s, v) {
					continue
				}
				end := valueEnd(s, v)
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
			v := skipBlanks(s, vs)
			if v >= len(s) || isTypeWord(s, v) || s[v] == '{' || isBlockIndicator(s, v) {
				continue
			}
			c.colonValue(name, v, flow && !lineHead, false)
		} else if !spaced && tight {
			if vs >= len(s) || s[vs] == '{' || isBlockIndicator(s, vs) || isTypeWord(s, vs) {
				continue
			}
			c.colonValue(name, vs, true, true)
		}
	}
}

// proseWords: a word that, after a credential's name mid-sentence, is the sentence going on, not a value
// (`the token: it expires`, `password: required`).
var proseWords = setOf("a", "an", "the", "is", "are", "was", "were", "be", "been", "it", "its", "this", "that", "these",
	"those", "and", "or", "not", "no", "yes", "to", "of", "in", "on", "for", "with", "from", "by", "at", "as", "if",
	"then", "when", "which", "who", "what", "how", "why", "where", "we", "you", "he", "she", "they", "i", "my", "your",
	"our", "their", "has", "have", "had", "do", "does", "did", "can", "could", "should", "would", "will", "may",
	"might", "must", "set", "unset", "use", "used", "using", "see", "null", "none", "nil", "true", "false", "empty",
	"required", "optional", "string", "str", "int", "number", "any", "unknown", "missing", "invalid", "expired",
	"needed", "here", "there", "same", "new", "old", "all", "each", "every", "only", "also", "just", "now", "redacted",
	"hidden", "masked", "secret", "value", "values", "none", "undefined", "todo", "tbd", "n/a", "xxx", "changeme")

// proseValue: the word at a credential's name mid-sentence is prose (or code), not a value.
func proseValue(v string) bool {
	w := strings.ToLower(strings.TrimRight(strings.Trim(v, "\"'`"), ".,;:!?)"))
	return w == "" || proseWords[w]
}

// strongProse: verbs a sentence or a commit message puts after a credential's name (`Fix token: refresh it`).
var strongProse = setOf("refresh", "refreshed", "rotate", "rotated", "reset", "revoke", "revoked", "renew", "renewed",
	"regenerate", "regenerated", "update", "updated", "change", "changed", "fix", "fixed", "add", "added", "remove",
	"removed", "check", "checked", "verify", "verified", "validate", "validated", "store", "stored", "save", "saved",
	"load", "loaded", "read", "write", "send", "sent", "handle", "handled", "parse", "parsed", "support", "clean",
	"expire", "expires", "rename", "renamed", "move", "moved", "keep", "kept", "drop", "dropped")

// plainWord: one word of three or more letters only that is not the sentence going on (`letmein`, not `required`
// or `refresh`).
func plainWord(v string) bool {
	if len(v) < 3 || proseValue(v) || strongProse[strings.ToLower(v)] {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !isLowerASCII(v[i]) && !isUpperASCII(v[i]) {
			return false
		}
	}
	return true
}

// minProseLongWord: mid-sentence, after a weaker credential name, a word of letters only this long or longer is a
// value; a shorter one is the sentence going on (`auth: rotated`), as an English word that long is rare.
const minProseLongWord = 13

// valueLike: mid-sentence, a word after a credential's name that reads as a value: holding a digit or a character
// no English word or identifier holds, or letters only and long; a short run of digits (`password: 0`) is a count,
// and letters joined by `-` `_` `.` are an identifier (`secret_scope`, `api-key-name`).
func valueLike(v string) bool {
	if v == "" || proseValue(v) {
		return false
	}
	digits, letters, sep, other := 0, 0, 0, 0
	for i := 0; i < len(v); i++ {
		switch ch := v[i]; {
		case isDigitASCII(ch):
			digits++
		case isLowerASCII(ch) || isUpperASCII(ch):
			letters++
		case ch == '-' || ch == '_' || ch == '.':
			sep++
		case ch <= ' ':
			return false // more than one word: a sentence
		case ch == '\'' && i > 0 && letters == i:
			return false // a possessive or a contraction (`someone's`, `don't`)
		default:
			other++
		}
	}
	switch {
	case letters == 0 && other == 0:
		return digits >= 6
	case digits > 0 || other > 0:
		return true
	case sep > 0:
		return false
	}
	if letters < minProseLongWord {
		return false
	}
	// Letters only and long: all lower case (no English word that long follows a credential's name), or upper
	// case mixed in at random; a type name's humps (`CredentialProvider`) are a few capitals in many letters.
	upper := 0
	for i := 1; i < len(v); i++ {
		if isUpperASCII(v[i]) {
			upper++
		}
	}
	return upper == 0 && isLowerASCII(v[0]) || upper*4 >= letters
}

// midValue: the value after a credential's name mid-sentence, from v: a quoted string that opens here and closes
// on its line (its body), else the word to a blank, without the wrapping a writer puts around it (`**x**`,
// `` `x` ``, `${x}`, curly quotes) or the punctuation that ends the sentence. A quote that closes a string opened
// earlier (`"invalid token: " + t`) holds no value. Returns the span to judge and hide, or ok false.
func midValue(s string, v int) (lo, hi int, ok bool) {
	le := lineEnd(s, v)
	if q := s[v]; q == '"' || q == '\'' || q == '`' {
		k := strings.IndexByte(s[v+1:le], q)
		if k <= 0 {
			return 0, 0, false
		}
		return v + 1, v + 1 + k, true
	}
	e := v
	// A written escape (`\n` in a JSON string) ends the word: the next line's text is not the value.
	for e < le && !isSpaceByte(s[e]) && !(s[e] == '\\' && e+1 < le && isAlnumASCII(s[e+1])) {
		e++
	}
	lo, hi = v, e
	for _, w := range []string{"**", "*", "${", "“", "‘", "(", "[", "<"} {
		if strings.HasPrefix(s[lo:hi], w) {
			lo += len(w)
			break
		}
	}
	for hi > lo {
		if strings.IndexByte(".,;:!?)]}>*`\"'", s[hi-1]) >= 0 {
			hi--
			continue
		}
		if strings.HasSuffix(s[lo:hi], "”") || strings.HasSuffix(s[lo:hi], "’") {
			hi -= len("”")
			continue
		}
		break
	}
	return lo, hi, hi > lo
}

// midColon: `name: value` in the middle of a line (`see HEROKU_API_KEY: c55d… here`). A credential's name
// hides the word after it when that word reads as a value; another keyword name hides a token word that looks
// random. Only a name standing as a word of its own; without a blank after the colon only a value with a digit
// (`password:Zk3mQ9`), so a URL's scheme or a time is not read.
func (c *scan) midColon(name string, q, p int) {
	s := c.s
	if q > 0 && !(isSpaceByte(s[q-1]) || strings.IndexByte(";\"'`([<>*", s[q-1]) >= 0) {
		return
	}
	if p+1 >= len(s) {
		return
	}
	spaced := s[p+1] == ' ' || s[p+1] == '\t'
	v := skipBlanks(s, p+1)
	// A reference, a format directive or a placeholder (`$TOKEN`, `%{http_code}`, `<redacted>`) is not a value.
	if v >= len(s) || s[v] == '$' || s[v] == '%' || s[v] == '{' || startsPlaceholder(s, v) || isTypeWord(s, v) || isBlockIndicator(s, v) {
		return
	}
	lo, hi, ok := midValue(s, v)
	// A placeholder inside the wrapping (`<<redacted>>`) is a value already hidden.
	if !ok || startsPlaceholder(s, lo) {
		return
	}
	val := s[lo:hi]
	if !spaced && (!IsCredentialName(name) || !strings.ContainsAny(val, "0123456789") || s[v] == '/') {
		return
	}
	// After a bracket a name and a colon may be a parameter and its type (`async (token: Promise<Token>) =>`):
	// only a value that looks random, or holds a digit and no type brackets, goes there.
	if q > 0 && strings.IndexByte("([<", s[q-1]) >= 0 && !LooksSecret(val) &&
		(!strings.ContainsAny(val, "0123456789") || strings.ContainsAny(val, "<>")) {
		return
	}
	if IsCredentialName(name) {
		// After a strong name a plain word is the value with a bracket after a blank too (`letmein (old)`): only one
		// glued to it is a call or an index.
		strong := strongCredentialName(name) && plainWord(val) && !(hi < len(s) && (s[hi] == '(' || s[hi] == '['))
		if strong || valueLike(val) && (!isCodeValue(s, lo) || LooksSecret(val)) {
			c.hideValue(lo, hi)
		}
		return
	}
	if tokenWord(val) && judged(name, val) {
		c.hideValue(lo, hi)
	}
}

// tokenWord: one word of token characters, quotes around it allowed: not code or a sentence.
func tokenWord(v string) bool {
	v = strings.Trim(v, "\"'")
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if ch := v[i]; !isAlnumASCII(ch) && strings.IndexByte("-_+/=.~:", ch) < 0 {
			return false
		}
	}
	return true
}

func (c *scan) colonValue(name string, v int, flow, tight bool) {
	s := c.s
	if IsCredentialName(name) {
		end := colonWords(s, v, flow, tight)
		c.hideColonBody(v, end, true)
		return
	}
	var end int
	if tight {
		end = valueEndFlow(s, v)
	} else {
		end = valueEnd(s, v)
	}
	if end > v && judged(name, s[v:end]) {
		c.hideColonBody(v, end, false)
	}
}

// hideColonBody: the value proper, without the `,` `;` `}` `]` that close the literal; a
// quoted value that closes keeps its quotes, any other goes whole.
// With words, the value is every word to a stop word: a placeholder then more words is a
// value partly sent (`authorization: <redacted> <token_or_cookie>`), and it goes whole.
func (c *scan) hideColonBody(a, b int, words bool) {
	for b > a && strings.IndexByte(",;}]", c.s[b-1]) >= 0 {
		b--
	}
	v := c.s[a:b]
	if len(v) > 1 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		c.hideValue(a+1, b-1)
		return
	}
	if words {
		c.hideWords(a, b)
		return
	}
	c.hideValue(a, b)
}

// quotedNameBeforeColon: `"name"` then whitespace or continuations (line breaks too) before p.
func (c *scan) quotedNameBeforeColon(p int) (int, int, bool) {
	s := c.s
	e := p
	for e > 0 {
		if isSpaceByte(s[e-1]) {
			e--
			continue
		}
		if e >= 2 && s[e-1] == '\n' && s[e-2] == '\\' {
			e -= 2
			continue
		}
		break
	}
	if e == 0 || (s[e-1] != '"' && s[e-1] != '\'') {
		return 0, 0, false
	}
	qe := e - 1
	q := nameRunBefore(s, qe)
	if q == qe || q == 0 || (s[q-1] != '"' && s[q-1] != '\'') {
		return 0, 0, false
	}
	return q, qe, true
}

// jsonField: `"name": "value"` (the name between quotes at [q, qe)); the value keeps its
// quotes and loses its body; unclosed, it runs to the line end.
func (c *scan) jsonField(q, qe, p int) {
	s := c.s
	name := trimDashes(s[q:qe])
	v := skipSpaceConts(s, p+1)
	if v >= len(s) || (s[v] != '"' && s[v] != '\'') {
		return
	}
	next := dqEndLine
	if s[v] == '\'' {
		next = sqEndEsc
	}
	end := c.r.quotedEnd(s, v, next)
	if !judged(name, s[v:end]) {
		return
	}
	// Closed only when the scan stopped on its own closing quote, not an escaped one.
	body := end
	if end > v+1 && s[end-1] == s[v] && !escapedAt(s, end-1) {
		body = end - 1
	}
	// A receiver reads the field's value to its quote: `<redacted>` alone is hidden, anything
	// else (a placeholder and a blank, or more) is a value partly sent.
	if inner := strings.TrimRight(s[v+1:end], s[v:v+1]); inner == "" || inner == phRedacted {
		return
	}
	c.hide(v+1, body, KindSecret)
}

// escapedAt: the character at i is escaped by an odd run of backslashes before it.
func escapedAt(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// objectAfter: the object a credential's name holds goes whole, to its matching brace.
func (c *scan) objectAfter(name string, p int) {
	s := c.s
	v := skipSpaceConts(s, p+1)
	if v >= len(s) || s[v] != '{' || (v+1 < len(s) && s[v+1] == '{') || !IsCredentialName(name) {
		return
	}
	end := objectEnd(s, v+1)
	if end > v+1 && s[end-1] == '}' {
		end--
	}
	c.hideValue(v+1, end)
}

// schemeAssigned: an assignment written after an auth scheme word (`Token password:x`).
func (c *scan) schemeAssigned(q int, name string, p int) {
	s := c.s
	j := q
	for j > 0 {
		if s[j-1] == ' ' || s[j-1] == '\t' {
			j--
			continue
		}
		if j >= 2 && s[j-1] == '\n' && s[j-2] == '\\' {
			j -= 2
			continue
		}
		break
	}
	if j == q {
		return
	}
	w := j
	for w > 0 && (isAlnumASCII(s[w-1]) || s[w-1] == '-') {
		w--
	}
	word := strings.ToLower(s[w:j])
	if !(authSchemes[word] || word == "apikey" || word == "api-key") {
		return
	}
	if w > 0 && (isLowerASCII(s[w-1]) || isUpperASCII(s[w-1])) {
		return
	}
	if !IsCredentialName(name) {
		return
	}
	vs := p + 1
	k := vs
	for k < len(s) && s[k] == '=' {
		k++
	}
	if k >= len(s) || isSpaceByte(s[k]) {
		return
	}
	c.hideValue(vs, valueEnd(s, vs))
}

// --- flags --------------------------------------------------------------------------------

// notAnOption: what is not an option's value: another option or `-`, or an operator.
func notAnOption(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	if s[i] == '-' {
		if i+1 < len(s) && s[i+1] == '-' {
			return false
		}
		j := i + 1
		if j < len(s) && isAlnumASCII(s[j]) {
			j++
		}
		if j >= len(s) || isSpaceByte(s[j]) || s[j] == '"' || s[j] == '\'' {
			return false
		}
	}
	j := i
	if j < len(s) && s[j] == ':' {
		j++
	}
	if j < len(s) && s[j] == '=' && (j+1 >= len(s) || isSpaceByte(s[j+1])) {
		return false
	}
	return true
}

// heredocAt: a real heredoc opener at i (`<<EOF` then a line break), its body's span.
func heredocAt(s string, i int) (bodyLo, bodyHi int, ok bool) {
	if !strings.HasPrefix(s[i:], "<<") {
		return 0, 0, false
	}
	j := i + 2
	if j < len(s) && (s[j] == '-' || s[j] == '~') {
		j++
	}
	var quote byte
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		quote = s[j]
		j++
	}
	w := j
	for j < len(s) && isWordAt(s, j) {
		j++
	}
	if j == w {
		return 0, 0, false
	}
	word := s[w:j]
	if quote != 0 {
		if j >= len(s) || s[j] != quote {
			return 0, 0, false
		}
		j++
	}
	le := lineEnd(s, j)
	rest := s[j:le]
	// An opener followed by an escaped line break is not one (JSON): the escaped heredoc.
	if strings.Contains(rest, `\n`) || le-j > 2000 || le >= len(s) {
		return 0, 0, false
	}
	body := le + 1
	k := body
	for n := 0; n < 200 && k < len(s); n++ {
		e := lineEnd(s, k)
		line := strings.TrimRight(s[k:e], "\r")
		if strings.TrimSpace(line) == word {
			break
		}
		if e >= len(s) {
			break // a body line must end with its line break
		}
		k = e + 1
	}
	if k > body && s[k-1] == '\n' {
		k-- // the last body line's break stays with the terminator
	}
	return body, k, true
}

// escapedHeredocEnd: a heredoc written with escaped line breaks (`<<EOF\nx\nEOF`): one
// word to the next real space.
func escapedHeredocEnd(s string, i int) int {
	if !strings.HasPrefix(s[i:], "<<") {
		return i
	}
	le := lineEnd(s, i)
	k := strings.Index(s[i:le], `\n`)
	if k < 0 {
		return i
	}
	j := i + k
	for j < le && !isSpaceByte(s[j]) && s[j] != '"' {
		if s[j] == '\\' && j+1 < le {
			j += 2
			continue
		}
		j++
	}
	return j
}

// flags: `--name value` and `-name value` for a credential's name, its heredoc, and the
// fixed `--password`-family flags.
func (c *scan) flags() {
	if off("flags") {
		return
	}
	s := c.s
	for i := strings.IndexByte(s, '-'); i >= 0; i = nextByte(s, '-', i+1) {
		// ASCII only: a non-ASCII letter glued before (`é--token x`) does not hide a flag.
		if i > 0 && (s[i-1] == '-' || isNameChar(s[i-1])) {
			continue
		}
		j := i + 1
		if j < len(s) && s[j] == '-' {
			j++
		}
		// More dashes (`---passwd x`): a password-family name after them is still `--passwd`.
		extra := false
		for j < len(s) && s[j] == '-' {
			j++
			extra = true
		}
		if j >= len(s) || !(isAlnumASCII(s[j]) || s[j] == '_') {
			continue
		}
		ne := nameRunAfter(s, j)
		name := s[j:ne]
		if !IsCredentialName(name) || (extra && !fixedFlag(name)) {
			continue
		}
		if extra {
			i = j - 2 // read as the double-dash flag it ends with
		}
		k := ne
		sep := skipBlanksConts(s, k)
		if sep == k {
			continue
		}
		if lo, hi, ok := heredocAt(s, skipBlanks(s, k)); ok {
			c.hideValue(lo, hi)
			// A password-family flag's value is also the word at the opener, as a receiver reading
			// `--token VALUE` takes it.
			if w := skipBlanks(s, k); j == i+2 && fixedFlag(name) {
				c.hideValue(w, valueEnd(s, w))
			}
			continue
		}
		v := sep
		if strings.HasPrefix(s[v:], "<<<") {
			// A here-string: the value is the word after it. A password-family flag's value is also
			// the word at the operator, as a receiver reading `--token VALUE` takes it.
			if j == i+2 && fixedFlag(name) {
				c.hideValue(v, valueEnd(s, v))
			}
			v = skipBlanks(s, v+3)
		}
		if v >= len(s) || (!notAnOption(s, v) && !(j == i+2 && (fixedFlag(name) || (alwaysValued(name) && !optionLike(s, v))))) {
			continue
		}
		if e := escapedHeredocEnd(s, v); e > v {
			c.hideValue(v, e)
			continue
		}
		c.hideValue(v, valueEnd(s, v))
	}
}

// fixedFlag: the password-family flags a receiver reads by name alone (`--token VALUE`).
// optionLike: the word at i reads as an option, not a value that starts with a dash: `-` (stdin), one letter
// (`-v`), or letters and dashes (`--verbose`, `-rf`). A password that starts with a dash holds more; so may
// what follows `=` in `--name=...`, which is taken as a value.
// A password-family flag (fixedFlag) takes even such a word, as a receiver reading `--token --x` does.
func optionLike(s string, i int) bool {
	if i >= len(s) || s[i] != '-' {
		return false
	}
	j := i
	for j < len(s) && s[j] == '-' {
		j++
	}
	k := j
	for k < len(s) && (isLowerASCII(s[k]) || isUpperASCII(s[k]) || s[k] == '-') {
		k++
	}
	if k == j && j == i+1 && j < len(s) && isAlnumASCII(s[j]) {
		k++ // `-1`, `-9`: one character
	}
	return k >= len(s) || isSpaceByte(s[k]) || s[k] == '"' || s[k] == '\'' || s[k] == ';' || s[k] == '|' || s[k] == '&' || s[k] == ')'
}

func fixedFlag(name string) bool {
	switch strings.ToLower(name) {
	case "password", "passwd", "token", "apikey", "api-key", "api_key", "secret", "auth", "auth-token":
		return true
	}
	return false
}

// alwaysValued: a double-dash flag whose next word is its value even when it looks like an
// option (`--password -Xy9`, `--token --verbose`): a password may start with a dash.
func alwaysValued(name string) bool { return fixedFlag(name) || IsCredentialName(name) }

// --- program options (R2) ----------------------------------------------------------------

// commandArgs: positions after a space or tab inside the command that starts at p, up to
// an unquoted `|` `;` `&` or the line end (continuations join), quoted arguments read whole.
func commandArgs(s string, p int, program string) []int {
	var out []int
	i := p + len(program)
	for i < len(s) {
		if n := contAt(s, i); n > 0 {
			i += n
			continue
		}
		c := s[i]
		if c == '\n' || c == '|' || c == ';' || c == '&' {
			break
		}
		if (i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || (i >= 2 && s[i-1] == '\n' && s[i-2] == '\\')) && i > p {
			out = append(out, i)
		}
		switch c {
		case '\\':
			i += 2
		case '\'':
			if k := strings.IndexByte(s[i+1:lineEnd(s, i+1)], '\''); k >= 0 {
				i += k + 2
			} else {
				i++
			}
		case '"':
			e := dqEndLine(s, i)
			if e > i+1 && s[e-1] == '"' {
				i = e
			} else {
				i++
			}
		default:
			i++
		}
	}
	return out
}

// programs: every mention of a program, at a word boundary.
func programs(s, program string) []int {
	var out []int
	low := asciiLower(s)
	for at := 0; ; {
		k := strings.Index(low[at:], program)
		if k < 0 {
			return out
		}
		p := at + k
		at = p + 1
		if p > 0 && wordBefore(s, p) {
			continue
		}
		if isWordAt(s, p+len(program)) {
			continue
		}
		out = append(out, p)
	}
}

type passwordOption struct {
	program  string
	option   string
	attached bool
	leftDash bool // the program must not follow a `-` (`login` in `docker login`, not `x-login`)
}

var passwordOptions = []passwordOption{
	{"login", "-p", true, true},
	{"sshpass", "-p", true, false},
	{"redis-cli", "-a", false, false},
	{"openssl", "-k", false, false},
	{"openssl", "-K", false, false},
}

func (c *scan) programOptions() {
	if off("options") {
		return
	}
	s := c.s
	for _, po := range passwordOptions {
		for _, p := range programs(s, po.program) {
			if po.leftDash && p > 0 && s[p-1] == '-' {
				continue
			}
			for _, a := range commandArgs(s, p, po.program) {
				if !strings.HasPrefix(s[a:], po.option) {
					continue
				}
				k := a + len(po.option)
				v := skipBlanksConts(s, k)
				if !po.attached && v == k {
					continue
				}
				if v >= len(s) || !notAnOption(s, v) {
					continue
				}
				c.hideValue(v, valueEnd(s, v))
			}
		}
	}
	c.curlUser()
	c.opensslPass()
	c.mysql()
	c.secretSet()
	c.npmAuth()
}

// curlUser: `curl -u user:password` and its spellings; everything after the user's colon.
func (c *scan) curlUser() {
	s := c.s
	for _, p := range programs(s, "curl") {
		for _, a := range commandArgs(s, p, "curl") {
			if s[a] != '-' {
				continue
			}
			v := -1
			switch {
			case strings.HasPrefix(s[a:], "--user") || strings.HasPrefix(s[a:], "--proxy-user"):
				k := a + len("--user")
				if strings.HasPrefix(s[a:], "--proxy-user") {
					k = a + len("--proxy-user")
				}
				if k < len(s) && s[k] == '=' {
					v = k + 1
				} else if e := skipBlanksConts(s, k); e > k {
					v = e
				}
			default:
				j := a + 1
				for j < len(s) && (isLowerASCII(s[j]) || isUpperASCII(s[j])) && s[j] != 'u' && s[j] != 'U' {
					j++
				}
				if j >= len(s) || (s[j] != 'u' && s[j] != 'U') {
					continue
				}
				k := j + 1
				if k < len(s) && (isLowerASCII(s[k]) || isUpperASCII(s[k])) {
					// glued user (`-uadmin:x`, the proxy's `-Uadmin:x`, and after other flags, `-kuadmin:x`: curl's
					// short options combine, and the one that takes a value takes the rest of the word)
					v = k
					break
				}
				if e := skipBlanksConts(s, k); e > k {
					v = e
				} else if k < len(s) && !isSpaceByte(s[k]) && s[k] != '-' {
					v = k
				}
			}
			if v < 0 || v >= len(s) {
				continue
			}
			c.userPassword(v)
		}
	}
}

// userPassword: in a `user:password` argument at v, hide everything after the user's colon.
func (c *scan) userPassword(v int) {
	s := c.s
	if s[v] == '"' || s[v] == '\'' {
		var end int
		if s[v] == '"' {
			end = dqEndLine(s, v)
		} else {
			end = sqEnd(s, v)
		}
		colon := strings.IndexByte(s[v:end], ':')
		if colon >= 0 {
			body := end
			if end > v+1 && s[end-1] == s[v] {
				body = end - 1
			}
			c.hideValue(v+colon+1, body)
			// A part glued after the closing quote is the same word.
			if body < end {
				c.hideValue(end, valueEnd(s, end))
			}
			return
		}
	}
	end := valueEnd(s, v)
	// The user may be quoted on its own (`"admin":x`); after its colon everything is the value.
	i := v
	for i < end {
		switch s[i] {
		case '"':
			i = dqEndLine(s, i)
			continue
		case '\'':
			i = sqEnd(s, i)
			continue
		case '\\':
			i += 2
			continue
		case ':':
			c.hideValue(i+1, end)
			return
		}
		i++
	}
}

var opensslPassRx = regexp.MustCompile(`-pass(?:in|out|word)?`)

func (c *scan) opensslPass() {
	s := c.s
	for _, m := range opensslPassRx.FindAllStringIndex(s, -1) {
		if m[0] > 0 && (wordBefore(s, m[0]) || s[m[0]-1] == '-') {
			continue
		}
		k := m[1]
		var v int
		if k < len(s) && s[k] == '=' {
			v = k + 1
		} else if e := skipBlanksConts(s, k); e > k {
			v = e
		} else {
			continue
		}
		if v >= len(s) {
			continue
		}
		if (s[v] == '"' || s[v] == '\'') && strings.HasPrefix(strings.ToLower(s[v+1:]), "pass:") {
			end := dqEndLine(s, v)
			if s[v] == '\'' {
				end = sqEnd(s, v)
			}
			body := end
			if end > v+1 && s[end-1] == s[v] {
				body = end - 1
			}
			c.hideValue(v+6, body)
			continue
		}
		if strings.HasPrefix(strings.ToLower(s[v:]), "pass:") {
			w := skipConts(s, v+5)
			c.hideValue(w, valueEnd(s, w))
		}
	}
}

func skipConts(s string, i int) int {
	for {
		n := contAt(s, i)
		if n == 0 {
			return i
		}
		i += n
	}
}

// mysql: every attached `-p` in a mysql or mysqldump command.
func (c *scan) mysql() {
	s := c.s
	for _, prog := range []string{"mysqldump", "mysql"} {
		for _, p := range programs(s, prog) {
			end := p
			for end < len(s) {
				if n := contAt(s, end); n > 0 {
					end += n
					continue
				}
				ch := s[end]
				if ch == '\n' || ch == '|' || ch == ';' || ch == '&' {
					break
				}
				end++
			}
			seg := s[:end]
			for i := p; i+2 < len(seg); i++ {
				if isSpaceByte(seg[i]) && seg[i+1] == '-' && seg[i+2] == 'p' {
					v := i + 3
					c.hideValue(v, valueEnd(seg, v))
				}
			}
		}
	}
}

var secretSetRx = regexp.MustCompile(`(?i)\bsecrets? set\b`)

// secretSet: `secret set NAME ... --body VALUE` / `-b VALUE` / `-bVALUE`.
func (c *scan) secretSet() {
	s := c.s
	for _, m := range secretSetRx.FindAllStringIndex(s, -1) {
		end := m[1]
		for end < len(s) {
			if n := contAt(s, end); n > 0 {
				end += n
				continue
			}
			if s[end] == '\n' {
				break
			}
			end++
		}
		for i := m[1]; i < end; i++ {
			if !isSpaceByte(s[i]) || i+2 >= len(s) || s[i+1] != '-' {
				continue
			}
			var k int
			switch {
			case strings.HasPrefix(s[i+1:], "--body"):
				k = i + 7
			case s[i+2] == 'b':
				k = i + 3
			default:
				continue
			}
			if k < len(s) && s[k] == '=' {
				k++
			} else {
				for k < len(s) {
					if isSpaceByte(s[k]) {
						k++
						continue
					}
					if n := contAt(s, k); n > 0 {
						k += n
						continue
					}
					break
				}
			}
			c.hideValue(k, valueEnd(s, k))
		}
	}
}

var npmAuthRx = regexp.MustCompile(`(?i):_(?:authToken|auth|password)["']?`)

func (c *scan) npmAuth() {
	s := c.s
	for _, m := range npmAuthRx.FindAllStringIndex(s, -1) {
		k := m[1]
		v := skipBlanksConts(s, k)
		if v == k || v >= len(s) || !notAnOption(s, v) {
			continue
		}
		c.hideValue(v, valueEnd(s, v))
	}
}

// --- headers and schemes (R3) ------------------------------------------------------------

var fixedHeaders = []string{"proxy-authorization", "authorization", "x-api-key", "api-key", "x-auth-token",
	"x-goog-api-key", "cookie"}

// hwordEnd: a header value's word: not a space, quote or backslash, except a backslash
// run before a space; continuations join.
func hwordEnd(s string, i int, cookie bool) int {
	j := i
	for j < len(s) {
		if n := contAt(s, j); n > 0 && j > i {
			k := skipConts(s, j)
			if k < len(s) && !isSpaceByte(s[k]) && s[k] != '"' && s[k] != '\'' {
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
		if isSpaceByte(ch) || ch == '"' || ch == '\'' || (cookie && ch == ';') {
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
	for j < len(s) && isSpaceByte(s[j]) {
		j++
	}
	if j >= len(s) || s[j] != ':' {
		return -1
	}
	j++
	if strings.HasPrefix(s[j:], `\ `) {
		return j + 2
	}
	return skipSpaceConts(s, j)
}

// closingQuote: where a header quoted with `open` closes, reading as each quoting allows;
// every reading that closes is returned.
func closingQuotes(s string, from int, open string) []int {
	var out []int
	switch open {
	case `"`:
		j := from
		for j < len(s) {
			if n := contAt(s, j); n > 0 {
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
			if n := contAt(s, j); n > 0 {
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
			if n := contAt(s, j); n > 0 {
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
		if n := contAt(s, j); n > 0 {
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
	for j > 0 && isSpaceByte(s[j-1]) {
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

func (c *scan) headers() {
	if off("headers") {
		return
	}
	s := c.s
	low := asciiLower(s)
	for _, h := range fixedHeaders {
		for at := 0; ; {
			k := strings.Index(low[at:], h)
			if k < 0 {
				break
			}
			q := at + k
			at = q + 1
			if q > 0 && wordBefore(s, q) {
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
			if f > 0 && (wordBefore(s, f) || s[f-1] == '-') {
				continue
			}
			j := f + len(flag)
			if j < len(s) && s[j] == '=' {
				j++
			} else {
				e := skipBlanks(s, j)
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
			j = skipBlanks(s, j)
			ne := nameRunAfter(s, j)
			if ne == j || !IsCredentialName(s[j:ne]) {
				continue
			}
			c.headerValue(j, ne, "", false)
		}
	}
}

// headerValue: the header named s[q:ne]; fixed tells a known header from a credential's name.
func (c *scan) headerValue(q, ne int, h string, fixed bool) {
	s := c.s
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
		_, e := crudeValue(s, v)
		c.hideQuotedBody(v, e)
	}
	// A known header in an object literal: its value's own `, k=v` parameters (Digest, SigV4)
	// read as the literal's next fields, so the value runs to the line end.
	if _, flow, tight := colonContext(s, q); fixed && (flow || tight) && open == "" {
		le := contLineEnd(s, v)
		if le > v && !onlyPlaceholders(s[v:le]) {
			c.hide(v, le, KindSecret)
			return
		}
	}
	// Unquoted, a value that opens a quoted part (`X-Token:'abc'`) is the shell word it starts. A
	// header name read inside a longer one (`api-key` in `'X-Api-Key:'`) is not unquoted.
	if open == "" && (q == 0 || !isNameChar(s[q-1])) && v < len(s) && (s[v] == '"' || s[v] == '\'') {
		c.hideQuotedBody(v, valueEnd(s, v))
	}
	switch {
	case h == "cookie":
		end := hwordEnd(s, v, true)
		for end < len(s) && s[end] == ';' {
			k := skipBlanksConts(s, end+1)
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
		if authSchemes[word] || word == "aws4-hmac-sha256" {
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
				if n := contAt(s, sep); n > 0 {
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
		if !fixed && authSchemes[strings.ToLower(s[v:end])] {
			k := skipBlanks(s, end)
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

var bearerProse = setOf("token", "tokens", "auth", "authentication", "authorization", "credential", "credentials", "jwt",
	"jwts", "scheme", "header", "bearer")

func isBearerChar(ch byte) bool {
	return isAlnumASCII(ch) || ch == '.' || ch == '_' || ch == '~' || ch == '+' || ch == '/' || ch == '-'
}

// bearer: the word after a Bearer scheme, unless it is prose ("a Bearer token.").
func (c *scan) bearer() {
	if off("bearer") {
		return
	}
	s := c.s
	low := asciiLower(s)
	for at := 0; ; {
		k := strings.Index(low[at:], "bearer")
		if k < 0 {
			return
		}
		b := at + k
		at = b + 1
		j := b + 6
		v := skipSpaceConts(s, j)
		if v == j || v >= len(s) {
			continue
		}
		// prose: the next word is one of these and nothing token-like follows it
		w := v
		for w < len(s) && isAlnumASCII(s[w]) {
			w++
		}
		if bearerProse[strings.ToLower(s[v:w])] {
			after := w
			tokenish := after < len(s) && (isAlnumASCII(s[after]) || strings.IndexByte("_~+/-=", s[after]) >= 0)
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
			if n := contAt(s, e); n > 0 {
				k := skipConts(s, e)
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

// --- .netrc ------------------------------------------------------------------------------

// netrcHead: where a .netrc entry may open: `machine` or `default` as a word of its own.
var netrcHead = regexp.MustCompile(`(?:^|[^\w.])(machine|default)[ \t]`)

// netrcWord: one .netrc token at i, after blanks and line breaks: a quoted string (raw or escaped) to its
// closing quote, else a run to a blank, a quote or a written escape (`\n` in a printf); an escaped space goes on.
// Returns the token's span, its body's span (inside quotes), or ok false at the end of the text.
func netrcWord(s string, i int) (lo, hi, blo, bhi int, ok bool) {
	for i < len(s) && isSpaceByte(s[i]) {
		i++
	}
	if i >= len(s) {
		return 0, 0, 0, 0, false
	}
	for _, q := range []string{`\"`, `"`, `'`} {
		if strings.HasPrefix(s[i:], q) {
			if k := strings.Index(s[i+len(q):], q); k >= 0 {
				e := i + len(q) + k
				return i, e + len(q), i + len(q), e, true
			}
		}
	}
	j := i
	for j < len(s) {
		ch := s[j]
		if ch == '\\' && j+1 < len(s) && s[j+1] == ' ' {
			j += 2
			continue
		}
		if isSpaceByte(ch) || ch == '"' || ch == '\'' || ch == '`' || (ch == '\\' && j+1 < len(s) && isAlnumASCII(s[j+1])) {
			break
		}
		j++
	}
	return i, j, i, j, j > i
}

// netrc: the passwords of a .netrc entry, on one line or several (`machine host login user password VALUE`). An
// entry is one with a dotted host or localhost, or a login before the password, so prose about a machine or a
// default password is not one.
func (c *scan) netrc() {
	s := c.s
	if !strings.Contains(s, "password") {
		return
	}
	for _, m := range netrcHead.FindAllStringSubmatchIndex(s, -1) {
		i := m[3]
		entry := false
		if s[m[2]:m[3]] == "machine" {
			lo, hi, _, _, ok := netrcWord(s, i)
			if !ok {
				continue
			}
			host := s[lo:hi]
			entry = strings.Contains(host, ".") || host == "localhost"
			i = hi
		}
		for {
			lo, hi, _, _, ok := netrcWord(s, i)
			if !ok {
				break
			}
			key := s[lo:hi]
			if key != "login" && key != "account" && key != "port" && key != "password" {
				break
			}
			_, vhi, blo, bhi, ok := netrcWord(s, hi)
			if !ok {
				break
			}
			if key == "login" {
				entry = true
			}
			if key == "password" && entry && bhi > blo {
				c.hideValue(blo, bhi)
			}
			i = vhi
		}
	}
}

// --- URL userinfo -------------------------------------------------------------------------

func (c *scan) userinfo() {
	if off("userinfo") {
		return
	}
	s := c.s
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
			if n := contAt(s, j); n > 0 {
				j += n
				continue
			}
			ch := s[j]
			if ch == '/' || isSpaceByte(ch) || ch == ':' || ch == '@' {
				break
			}
			j++
		}
		// An empty user (`redis://:password@host`) still has a password.
		if j >= len(s) || s[j] != ':' {
			continue
		}
		v := j + 1
		e := skipConts(s, v)
		for e < len(s) {
			if n := contAt(s, e); n > 0 {
				e += n
				continue
			}
			ch := s[e]
			if ch == '@' || isSpaceByte(ch) {
				break
			}
			e++
		}
		if e >= len(s) || s[e] != '@' || e == skipConts(s, v) {
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
			if isSpaceByte(ch) || strings.IndexByte("\"'`<>[]()", ch) >= 0 {
				break
			}
		}
		c.hideValue(v, e)
	}
}

// --- quoted words: fields and whole assignments ------------------------------------------

// quotedWords: the shell-quoted words, left to right: `"..."` with escapes, `'...'`
// without, each to its closing quote or its line's end.
func quotedWords(s string) [][2]int {
	var out [][2]int
	i := 0
	for i < len(s) {
		ch := s[i]
		if (ch == '"' || ch == '\'') && !(i > 0 && s[i-1] == '\\') {
			var e int
			if ch == '"' {
				e = i + 1
				for e < len(s) {
					if s[e] == '\\' && e+1 < len(s) && s[e+1] != '\n' {
						e += 2
						continue
					}
					if s[e] == '"' {
						e++
						break
					}
					if s[e] == '\\' || s[e] == '\n' {
						break
					}
					e++
				}
			} else {
				le := lineEnd(s, i+1)
				if k := strings.IndexByte(s[i+1:le], '\''); k >= 0 {
					e = i + 1 + k + 1
				} else {
					e = le
				}
			}
			out = append(out, [2]int{i, e})
			i = e
			if i == out[len(out)-1][0] {
				i++
			}
			continue
		}
		i++
	}
	return out
}

// quotedAssignments: a quoted word that opens with a credential's assignment holds the value
// to its closing quote (`"token=a b"`); a later `&name=` field in one does the same.
func (c *scan) quotedAssignments() {
	if off("quoted") {
		return
	}
	s := c.s
	for _, w := range quotedWords(s) {
		a, b := w[0], w[1]
		q := s[a]
		inner := b
		if b > a+1 && s[b-1] == q {
			inner = b - 1
		}
		// whole assignment
		j := a + 1
		for j < inner && s[j] == '-' {
			j++
		}
		ne := nameRunAfter(s, j)
		if ne > j && ne < len(s) && s[ne] == '=' && IsCredentialName(s[j:ne]) {
			c.hideWords(ne+1, assignedInQuotesEnd(s, ne+1, q))
		}
		// fields
		for p := a + 1; p < inner; p++ {
			if s[p] != '=' {
				continue
			}
			nq := nameRunBefore(s, p)
			if nq == p {
				continue
			}
			k := nq
			for k > a+1 && s[k-1] == '.' {
				k2 := nameRunBefore(s, k-1)
				if k2 == k-1 {
					break
				}
				k = k2
			}
			if k <= a+1 || strings.IndexByte("&?;,", s[k-1]) < 0 {
				continue
			}
			if IsCredentialName(s[nq:p]) {
				// The field holds its value to the word's closing quote: a placeholder and
				// more (`?token=<redacted> +rest"`) is a value partly sent.
				c.hideWords(p+1, fieldEnd(s, p+1, inner))
			}
		}
	}
	c.escapedQuoteAssignments()
	c.closedQuoteAssignments()
}

// closedQuoteAssignments: `"NAME=value"` or `'NAME=value'` wherever a quote opens one, a quoted
// word inside another included (`'... "token=a b" ...'`, which the left-to-right reading pairs
// the other way): a closed quoted assignment holds its value to its closing quote.
func (c *scan) closedQuoteAssignments() {
	s := c.s
	for i := 0; i < len(s); i++ {
		q := s[i]
		if (q != '"' && q != '\'') || (i > 0 && s[i-1] == '\\') {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] == '-' {
			j++
		}
		ne := nameRunAfter(s, j)
		if ne == j || ne >= len(s) || s[ne] != '=' || !(isAlnumASCII(s[j]) || s[j] == '_') || !IsCredentialName(s[j:ne]) {
			continue
		}
		e := ne + 1
		for e < len(s) && s[e] != '\n' && s[e] != q {
			if q == '"' && s[e] == '\\' && e+1 < len(s) && s[e+1] != '\n' {
				e += 2
				continue
			}
			e++
		}
		if e < len(s) && s[e] == q && e > ne+1 && !placeholderValue(s[ne+1:e]) {
			c.hide(ne+1, e, KindSecret)
		}
	}
}

// assignedInQuotesEnd: a whole assignment's value inside a quoted word: in double quotes an
// escape (a continuation too) is the value's, and it ends at the closing quote or the line
// end; in single quotes, at the closing quote or the line end.
func assignedInQuotesEnd(s string, i int, q byte) int {
	j := i
	for j < len(s) {
		if q == '"' && s[j] == '\\' {
			if j+2 < len(s) && s[j+1] == '\r' && s[j+2] == '\n' {
				j += 3
				continue
			}
			j += 2
			continue
		}
		if s[j] == q || s[j] == '\n' {
			break
		}
		j++
	}
	if j > len(s) {
		j = len(s)
	}
	return j
}

// fieldEnd: a value inside a quoted word, to the word's closing quote or a line break.
func fieldEnd(s string, i, limit int) int {
	j := i
	for j < limit {
		if s[j] == '\\' && j+1 < limit {
			j += 2
			continue
		}
		if s[j] == '\n' {
			return j
		}
		j++
	}
	if j > limit {
		j = limit
	}
	return j
}

// escapedQuoteAssignments: `\"token=a b\"`, a level down: to the next escaped quote.
func (c *scan) escapedQuoteAssignments() {
	s := c.s
	for at := 0; ; {
		k := strings.Index(s[at:], `\"`)
		if k < 0 {
			return
		}
		p := at + k + 2
		at = p
		j := p
		for j < len(s) && s[j] == '-' {
			j++
		}
		ne := nameRunAfter(s, j)
		if ne == j || ne >= len(s) || s[ne] != '=' || !IsCredentialName(s[j:ne]) {
			continue
		}
		e := ne + 1
		for e < len(s) && s[e] != '"' && s[e] != '\n' {
			e++
		}
		c.hideValue(ne+1, e)
	}
}
