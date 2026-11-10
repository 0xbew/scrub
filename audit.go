package scrub

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Hit is an audit rule id. The audit returns rule ids, never the text it found.
type Hit = string

// The audit reads what is about to be sent the way the receiver will: every reading of the
// text (as written, each level of backslash escapes removed, percent-decoded). It shares the
// readings and the classifiers with the scrubber, and nothing else: its names and value
// extents are its own crude code, so one lexer fault cannot blind both.

// Audit returns the rule ids that fire anywhere in text.
func Audit(text string, d *Denylist) []Hit { return auditTexts([]string{text}, d) }

// AuditValue: Audit over every string in a JSON-shaped value, keys included.
func AuditValue(v any, d *Denylist) []Hit {
	var texts []string
	stack := []any{v}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch x := item.(type) {
		case string:
			texts = append(texts, x)
		case map[string]any:
			for k, val := range x {
				texts = append(texts, k)
				stack = append(stack, val)
			}
		case []any:
			stack = append(stack, x...)
		}
	}
	return auditTexts(texts, d)
}

// AuditBody: Audit over a JSON document or JSON lines, decoded as the receiver reads them. A
// body that cannot be decoded is `unreadable`: it cannot be shown clean.
func AuditBody(body []byte, d *Denylist) []Hit {
	if d == nil {
		return []Hit{"denylist:none"}
	}
	if !utf8Valid(body) {
		return []Hit{"unreadable"}
	}
	var values []any
	var one any
	if err := json.Unmarshal(body, &one); err == nil {
		values = append(values, one)
	} else {
		for _, line := range bytes.Split(body, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var v any
			if err := json.Unmarshal(line, &v); err != nil {
				return []Hit{"unreadable"}
			}
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return []Hit{"unreadable"}
	}
	return AuditValue(values, d)
}

func utf8Valid(b []byte) bool { return strings.ToValidUTF8(string(b), "\x00") == string(b) }

func auditTexts(texts []string, d *Denylist) []Hit {
	// No denylist at all (nil) is a configured list that could not be loaded: refuse. NoDenylist is the choice to go without.
	if d == nil {
		return []Hit{"denylist:none"}
	}
	var hits []Hit
	add := func(rule string, found bool) {
		if found {
			hits = append(hits, rule)
		}
	}
	any := func(f func(string) bool) bool {
		for _, t := range texts {
			if f(t) {
				return true
			}
		}
		return false
	}
	// Every reading of every text, read once; shapes and the denylist skip a joined one.
	var apart, unescaped []string
	var all []*reading
	for _, t := range texts {
		for _, r := range readingsOf(rawReading(t), true) {
			all = append(all, r)
			if !r.joined {
				apart = append(apart, r.text)
				if r.kind != readRaw && !r.pctd {
					unescaped = append(unescaped, r.text)
				}
			}
		}
	}
	// The safety net's own checks (audit_net.go): what a blind detector would let through, refused anyway.
	net := netHits(all, d)
	add("email", anyOf(apart, hasEmail) || net["email"])
	// Phones as the scrubber reads them: not percent-decoded, where `+` is a space.
	add("phone", any(hasPhone) || anyOf(unescaped, hasPhone) || net["phone"])
	if d != nil {
		for _, id := range d.identities {
			id := id
			add(id.rule, anyOf(apart, func(t string) bool { return matchesWithBoundary(id.rx, t, id.literal) }) || net[id.rule])
		}
		for _, v := range d.vendors {
			v := v
			add(v.rule, anyOf(apart, func(t string) bool { return v.rx.MatchString(t) }))
		}
	}
	found := map[string]bool{}
	for rule, hit := range net {
		if hit && strings.HasPrefix(rule, "secret:") {
			found[rule] = true
		}
	}
	for _, t := range texts {
		for _, r := range readingsOf(rawReading(t), true) {
			if !found["secret:token-format"] && hasToken(r.text) {
				found["secret:token-format"] = true
			}
			if !found["secret:jwt"] && hasJWT(r.text) {
				found["secret:jwt"] = true
			}
			if !r.joined && !found["secret:long-run"] && hasLongRun(r) {
				found["secret:long-run"] = true
			}
			a := &auditor{r: r, s: r.text, pct: r.pct, found: found}
			a.run()
		}
	}
	for _, rule := range []string{"secret:token-format", "secret:jwt", "secret:long-run", "secret:json-field", "secret:named-value", "secret:flag-value",
		"secret:header", "secret:scheme-value", "secret:colon-value"} {
		add(rule, found[rule])
	}
	return hits
}

// hasJWT: the audit's own JWT reading, not the scrubber's pattern: `eyJ` and three dot-joined base64url
// segments of at least 5 characters each after a word's start, of at least 10 glued to a word before it.
func hasJWT(s string) bool {
	for i := strings.Index(s, "eyJ"); i >= 0; {
		min := 5
		if i > 0 && (isAlnumASCII(s[i-1]) || s[i-1] == '_') {
			min = 10
		}
		j, segs := i, 0
		for segs < 3 {
			k := j
			for k < len(s) && (isAlnumASCII(s[k]) || s[k] == '-' || s[k] == '_') {
				k++
			}
			// The first segment's `eyJ` does not count toward its length, as the scrubber's patterns read it.
			need := min
			if segs == 0 {
				need += 3
			}
			if k-j < need {
				if segs == 0 {
					j = k
				}
				break
			}
			segs++
			if segs < 3 {
				if k >= len(s) || s[k] != '.' {
					break
				}
				k++
			}
			j = k
		}
		if segs == 3 && !onlyPlaceholders(s[i:j]) {
			return true
		}
		// On past the run just read, so a long run of `eyJ` is read once, not once per `eyJ`.
		from := i + 3
		if j > from {
			from = j
		}
		if from >= len(s) {
			break
		}
		n := strings.Index(s[from:], "eyJ")
		if n < 0 {
			break
		}
		i = from + n
	}
	return false
}

// receiverValueEnd: `"(?:\\.|[^"\\\n])*"?`, `'[^'\n]*'?` or `[^\s"']+` at i.
func receiverValueEnd(s string, i int) int {
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '"':
		return dqEndLine(s, i)
	case '\'':
		le := lineEnd(s, i+1)
		if k := strings.IndexByte(s[i+1:le], '\''); k >= 0 {
			return i + 1 + k + 1
		}
		return le
	}
	j := i
	for j < len(s) && !isSpaceByte(s[j]) && s[j] != '"' && s[j] != '\'' {
		j++
	}
	return j
}

// looksSecretOrFirstWord: the value, or its first word, looks random (a value read on past a
// quote written another way can hold words after the secret).
func looksSecretOrFirstWord(v string) bool {
	if LooksSecret(v) {
		return true
	}
	f := strings.Fields(strings.Trim(v, "\"'"))
	return len(f) > 0 && LooksSecret(f[0])
}

func anyOf(texts []string, f func(string) bool) bool {
	for _, t := range texts {
		if f(t) {
			return true
		}
	}
	return false
}

// hasPhone: a phone shape in any text the phone rule reads (phoneReadings).
func hasPhone(text string) bool {
	for _, r := range phoneReadings(text) {
		if hasPhoneShape(r.text) {
			return true
		}
	}
	return false
}

// pieces builds a reading from pieces of a source text, each mapped to its own bytes.
type pieces struct {
	src string
	b   strings.Builder
	lo  []int32
	hi  []int32
}

func (p *pieces) add(from, to int) {
	for i := from; i < to; i++ {
		p.b.WriteByte(p.src[i])
		p.lo = append(p.lo, int32(i))
		p.hi = append(p.hi, int32(i+1))
	}
}

func (p *pieces) reading() *reading {
	return &reading{text: p.b.String(), lo: p.lo, hi: p.hi, src: p.src}
}

// phoneReadings: each side of a whole diff hunk (as many rows as its header counts) on its
// own, its rows without their marker, so the `+` that marks an added row is never a country
// code's; a hunk that stops short, and every other line, read as written. Each is a reading
// mapped onto text, so the scrubber hides what the audit finds there.
func phoneReadings(text string) []*reading {
	var out []*reading
	type line struct{ start, end int }
	var written []line
	type held struct {
		line   line
		marker string
	}
	var hold []held
	join := func(ls []line) *reading {
		p := &pieces{src: text}
		for _, l := range ls {
			p.add(l.start, l.end)
		}
		return p.reading()
	}
	oldN, newN := 0, 0
	for _, ln := range diffLines(text) {
		l := line{ln.start, ln.end}
		marker := ""
		if ln.end > ln.start {
			marker = text[ln.start : ln.start+1]
		}
		if oldN > 0 || newN > 0 {
			row := (marker == "+" && newN > 0) || (marker == "-" && oldN > 0) ||
				((marker == " " || marker == "\n" || marker == "\r") && oldN > 0 && newN > 0)
			if row || marker == "\\" {
				if row {
					if marker != "+" {
						oldN--
					}
					if marker != "-" {
						newN--
					}
				}
				hold = append(hold, held{l, marker})
				if oldN == 0 && newN == 0 {
					out = append(out, join(written))
					for _, side := range []string{"+", "-"} {
						p := &pieces{src: text}
						for _, h := range hold {
							if h.marker == side || h.marker == " " || h.marker == "\n" || h.marker == "\r" {
								if h.marker == "+" || h.marker == "-" || h.marker == " " {
									p.add(h.line.start+1, h.line.end)
								} else {
									p.add(h.line.start, h.line.end)
								}
							}
						}
						out = append(out, p.reading())
					}
					for _, h := range hold {
						if h.marker == "\\" {
							out = append(out, join([]line{h.line}))
						}
					}
					written, hold = nil, nil
				}
				continue
			}
			for _, h := range hold {
				written = append(written, h.line)
			}
			hold, oldN, newN = nil, 0, 0
		}
		if o, n, _, ok := hunkHeader(text[ln.start:ln.body]); ok {
			oldN, newN = o, n
		}
		written = append(written, l)
	}
	for _, h := range hold {
		written = append(written, h.line)
	}
	return append(out, join(written))
}

type auditor struct {
	r     *reading
	s     string
	pct   bool
	found map[string]bool
	spans *spanSet // set when locating
}

func (a *auditor) hit(rule string) { a.found[rule] = true }

// hitAt: a hit whose value is s[lo:hi]; when the auditor locates, the value's source span is
// kept, so the scrubber can hide what its own audit still reads as sent (see locateLive).
func (a *auditor) hitAt(rule string, lo, hi int) {
	a.hit(rule)
	if a.spans != nil && lo < hi {
		slo, shi := a.r.source(lo, hi)
		a.spans.add(slo, shi, KindSecret)
	}
}

// crudeValue: the audit's own value extent at i: a quoted value to its closing quote on its
// line (or the line end), else a word to a space, a quote or `,` `;` `}` `]`.
func crudeValue(s string, i int) (int, int) {
	if i >= len(s) {
		return i, i
	}
	switch s[i] {
	case '"':
		j := i + 1
		for j < len(s) && s[j] != '\n' {
			if s[j] == '\\' && j+1 < len(s) && s[j+1] != '\n' {
				j += 2
				continue
			}
			if s[j] == '"' {
				return i, j + 1
			}
			j++
		}
		return i, j
	case '\'', '`':
		q := s[i]
		j := i + 1
		for j < len(s) && s[j] != '\n' && s[j] != q {
			j++
		}
		if j < len(s) && s[j] == q {
			j++
		}
		return i, j
	}
	j := i
	for j < len(s) && !isSpaceByte(s[j]) && s[j] != '"' && s[j] != '\'' {
		j++
	}
	return i, j
}

// live: a value that still holds something other than placeholders, quotes and escapes.
func live(v string) bool {
	t := strings.Trim(v, " \t\r\n\"'`\\,;")
	if t == "" {
		return false
	}
	return !onlyPlaceholders(t)
}

// schemeWord: a value that opens with an auth scheme takes the word after it too.
func schemeValue(s string, i int) (int, int) {
	w := i
	for w < len(s) && isAlnumASCII(s[w]) {
		w++
	}
	if w > i && authSchemes[strings.ToLower(s[i:w])] {
		k := skipBlanks(s, w)
		if k > w && k < len(s) {
			_, e := crudeValue(s, k)
			return i, e
		}
	}
	return crudeValue(s, i)
}

func (a *auditor) run() {
	a.heredocValues()
	a.assignments()
	a.colons()
	a.flags()
	a.options()
	a.headers()
	if !a.pct {
		a.code()
	}
}

// heredocValues: a heredoc opening a credential's value whose body holds more than placeholders (detect.go's
// heredocValues, the shape the scrubber hides).
func (a *auditor) heredocValues() {
	heredocValues(a.s, func(lo, hi int) {
		if live(a.s[lo:hi]) {
			a.hit("secret:named-value")
		}
	})
}

// assignments: any name, `=`, a value.
func (a *auditor) assignments() {
	s := a.s
	for p := strings.IndexByte(s, '='); p >= 0; p = nextByte(s, '=', p+1) {
		q := nameRunBefore(s, p)
		var name string
		switch {
		case q < p:
			name = trimDashes(s[q:p])
		case p > 0 && (s[p-1] == '"' || s[p-1] == '\''):
			e := p - 1
			for e > 0 && s[e-1] == '\\' {
				e--
			}
			q2 := nameRunBefore(s, e)
			if q2 == e {
				continue
			}
			name = trimDashes(s[q2:e])
		case p > 0 && (s[p-1] == ' ' || s[p-1] == '\t'):
			// Code's `name = value`: a value that holds a placeholder and more (`<redacted>[0]`,
			// `<redacted>/`) is a value partly sent, as a receiver splits it at a space or quote.
			a.spacedAssignment(p)
			continue
		default:
			continue
		}
		if name == "" {
			continue
		}
		// As a receiver splits `NAME=` from what follows: a quoted string from the `=` on, or a
		// run to a space or quote. Anything there but `<redacted>` is a value, `;`, `)` and a
		// placeholder with a closer glued to it too: an empty assignment (`NAME=;`) is refused
		// rather than judged.
		if q < p && IsCredentialName(name) {
			if e := receiverValueEnd(s, p+1); strings.Trim(s[p+1:e], "\"'") != "" && strings.Trim(s[p+1:e], "\"'") != phRedacted {
				a.hitAt("secret:named-value", p+1, e)
			} else if e == p+1 {
				// Nothing glued to `NAME=`: the receiver reads on past blanks and line breaks to a quoted string,
				// which is the value when the scrubber hid part of it (`NAME=` then `"echo <redacted>"`).
				w := p + 1
				for w < len(s) && isSpaceByte(s[w]) {
					w++
				}
				if w > p+1 && w < len(s) && (s[w] == '"' || s[w] == '\'') {
					e := receiverValueEnd(s, w)
					if v := strings.Trim(s[w:e], "\"'"); strings.Contains(v, "<redacted") && v != phRedacted {
						a.hitAt("secret:named-value", w, e)
					}
				}
			}
		}
		lo, hi := schemeValue(s, p+1)
		v := s[lo:hi]
		vlo, vhi := lo, hi
		// A quoted word that opens with the assignment holds its value to the closing quote.
		if q < p {
			k := q
			for k < p && s[k] == '-' {
				k++
			}
			if q > 0 && (s[q-1] == '"' || s[q-1] == '\'') {
				qc := s[q-1]
				e := p + 1
				for e < len(s) && s[e] != qc && s[e] != '\n' {
					e++
				}
				v = s[p+1 : e]
				vlo, vhi = p+1, e
			}
		}
		if !live(v) {
			continue
		}
		if IsCredentialName(name) || (hasKeyword(name) && LooksSecret(v)) {
			a.hitAt("secret:named-value", vlo, vhi)
		}
	}
}

// spacedAssignment: `name = value` at the `=` at p, judged only when the value opens with a placeholder and more
// is glued to it: the scrubber hid part of it, and the rest is that value's (`(<redacted>,` is a tuple's item).
func (a *auditor) spacedAssignment(p int) {
	s := a.s
	e := p
	for e > 0 && (s[e-1] == ' ' || s[e-1] == '\t') {
		e--
	}
	q := nameRunBefore(s, e)
	if q == e || !IsCredentialName(trimDashes(s[q:e])) || (p+1 < len(s) && s[p+1] == '=') || (e > 0 && strings.IndexByte("!<>=", s[e-1]) >= 0) {
		return
	}
	v := skipBlanks(s, p+1)
	if v == p+1 || v >= len(s) {
		return
	}
	end := v
	for end < len(s) && !isSpaceByte(s[end]) && s[end] != '"' && s[end] != '\'' && s[end] != '`' {
		end++
	}
	// What closes the statement around it (`)` `,` `;` `]` `}`) and a trailing escape are not the value's.
	val := strings.TrimRight(s[v:end], "\\),;]}")
	if strings.HasPrefix(val, "<redacted") && val != phRedacted {
		a.hitAt("secret:named-value", v, end)
	}
}

// colons: `"name": value` anywhere, `name: value` first on a line or after `{` `,`.
func (a *auditor) colons() {
	s := a.s
	for p := strings.IndexByte(s, ':'); p >= 0; p = nextByte(s, ':', p+1) {
		e := p
		for e > 0 && isSpaceByte(s[e-1]) {
			e--
		}
		quoted := e > 0 && (s[e-1] == '"' || s[e-1] == '\'')
		ne := e
		if quoted {
			ne = e - 1
			for ne > 0 && s[ne-1] == '\\' {
				ne--
			}
		}
		q := nameRunBefore(s, ne)
		if q == ne {
			continue
		}
		name := trimDashes(s[q:ne])
		v := skipSpaceConts(s, p+1)
		if quoted && q > 0 && (s[q-1] == '"' || s[q-1] == '\'') {
			if v < len(s) && (s[v] == '"' || s[v] == '\'') {
				lo, hi := v, a.r.quotedEnd(s, v, func(s string, i int) int { _, e := crudeValue(s, i); return e })
				val := s[lo:hi]
				// The value to its quote: anything but `<redacted>` is a value (a placeholder and a
				// blank too), as Python's audit reads a field.
				inner := strings.TrimRight(s[lo+1:hi], s[lo:lo+1])
				if inner != "" && inner != phRedacted && (IsCredentialName(name) || (hasKeyword(name) && looksSecretOrFirstWord(val))) {
					a.hitAt("secret:json-field", lo, hi)
				}
			}
			if v < len(s) && s[v] == '[' && !a.pct && IsCredentialName(name) && arrayLive(s, v) {
				a.hitAt("secret:json-field", v+1, arrayBodyEnd(s, v))
			}
			continue
		}
		if !IsCredentialName(name) {
			continue
		}
		if v < len(s) && s[v] == '[' && !a.pct && arrayLive(s, v) {
			a.hitAt("secret:json-field", v+1, arrayBodyEnd(s, v))
		}
		ls := lineStart(s, q)
		head := strings.Trim(s[ls:q], " \t+-") == ""
		j := q
		for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '+' || s[j-1] == '-') {
			j--
		}
		flow := j > 0 && (s[j-1] == '{' || s[j-1] == ',')
		if !head && !flow {
			continue
		}
		w := skipBlanks(s, p+1)
		if head && !flow && w == p+1 {
			continue
		}
		if w >= len(s) || s[w] == '{' || isTypeWord(s, w) {
			continue
		}
		if isBlockIndicator(s, w) {
			if !a.pct && blockLive(s, w) {
				a.hit("secret:colon-value")
			}
			continue
		}
		// A known header's value in an object literal runs to the line end (its own `, k=v`).
		if flow && isFixedHeader(name) {
			if le := contLineEnd(s, w); live(s[w:le]) {
				a.hitAt("secret:colon-value", w, le)
			}
			continue
		}
		// a value, then every word after a blank that is not a stop word
		end := auditWordEnd(s, w, true)
		for {
			k := skipBlanks(s, end)
			if k == end || k >= len(s) || colonStop(s, k) {
				break
			}
			e2 := auditWordEnd(s, k, false)
			if e2 == k {
				break
			}
			end = e2
		}
		if live(s[w:end]) {
			a.hitAt("secret:colon-value", w, end)
		}
	}
}

// auditWordEnd: `"..."?`, `'...'?`, or a run without a space, quote or `,` `;` `}` `]`; the
// first word may be an auth scheme and the word after it.
func auditWordEnd(s string, i int, first bool) int {
	if i >= len(s) {
		return i
	}
	if s[i] == '"' || s[i] == '\'' {
		_, e := crudeValue(s, i)
		return e
	}
	j := i
	for j < len(s) && !isSpaceByte(s[j]) && strings.IndexByte("\"',;}]", s[j]) < 0 {
		j++
	}
	if first && authSchemes[strings.ToLower(s[i:j])] {
		k := skipBlanks(s, j)
		if k > j && k < len(s) {
			e := k
			for e < len(s) && !isSpaceByte(s[e]) && strings.IndexByte("\"',;}]", s[e]) < 0 {
				e++
			}
			if e > k {
				return e
			}
		}
	}
	return j
}

// arrayBodyEnd: where the array opening at v ends, as arrayEnd reads it (past a `]` inside a
// string, so it covers the first-`]` reading too).
func arrayBodyEnd(s string, v int) int { return arrayEnd(s, v) }

func arrayLive(s string, v int) bool {
	end := len(s)
	if k := strings.IndexByte(s[v:], ']'); k >= 0 {
		end = v + k
	}
	if end-v > 4000 {
		end = v + 4000
	}
	// The array to its first `]`, and to the `]` that closes it with strings skipped.
	return arrayLiveTo(s, v, end) || arrayLiveTo(s, v, arrayEnd(s, v))
}

func arrayLiveTo(s string, v, end int) bool {
	if end <= v {
		return false
	}
	body := s[v+1 : end]
	for _, part := range strings.FieldsFunc(body, func(r rune) bool { return r == ',' || r == '\n' }) {
		p := strings.TrimSpace(part)
		p = strings.TrimLeft(p, "+-")
		if live(p) {
			return true
		}
	}
	return false
}

func blockLive(s string, w int) bool {
	le := lineEnd(s, w)
	indent := func(i int) int {
		j := i
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++ // a diff row's marker
		}
		k := j
		for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
			k++
		}
		return k - j
	}
	key := indent(lineStart(s, w))
	for i := le + 1; i < len(s); {
		e := lineEnd(s, i)
		line := strings.TrimLeft(s[i:e], "+- \t\r")
		if line != "" {
			// A block's body is indented past its key; a line that is not is the next key, and the block is empty.
			return indent(i) > key && live(line)
		}
		if e >= len(s) {
			break
		}
		i = e + 1
	}
	return false
}

// flags: a credential's flag before a space or a continuation, and its value.
func (a *auditor) flags() {
	s := a.s
	for i := strings.IndexByte(s, '-'); i >= 0; i = nextByte(s, '-', i+1) {
		// ASCII only: a non-ASCII letter glued before (`é--token x`) does not hide a flag.
		if i > 0 && (s[i-1] == '-' || isNameChar(s[i-1])) {
			continue
		}
		// A single dash at a line's start is a removed diff row's marker.
		j := i + 1
		if j < len(s) && s[j] == '-' {
			j++
		} else if i == 0 || s[i-1] == '\n' {
			continue
		}
		// More dashes (`---passwd x`): only a password-family name after them is a flag, as a
		// receiver reads `--passwd` inside it; `---DSN start---` is a separator.
		extra := false
		for j < len(s) && s[j] == '-' {
			j++
			extra = true
		}
		ne := nameRunAfter(s, j)
		if ne == j || !(isAlnumASCII(s[j]) || s[j] == '_') || !IsCredentialName(s[j:ne]) || (extra && !fixedFlag(s[j:ne])) {
			continue
		}
		// Blanks and continuations, but not one into a diff's `-` or `+` row.
		v := ne
		for v < len(s) {
			if s[v] == ' ' || s[v] == '\t' {
				v++
				continue
			}
			// Percent-decoded, a diff row's `+` reads as a space: no continuation there.
			if n := contAt(s, v); n > 0 && !a.pct && !(v+n < len(s) && (s[v+n] == '+' || s[v+n] == '-')) {
				v += n
				continue
			}
			break
		}
		if v == ne || (v < len(s) && contAt(s, v) > 0) {
			continue
		}
		if lo, hi, ok := heredocAt(s, skipBlanks(s, ne)); ok {
			if !a.pct && hi > lo && live(heredocFirstLine(s, lo)) {
				a.hit("secret:flag-value")
			}
			continue
		}
		if strings.HasPrefix(s[v:], "<<<") {
			v = skipBlanks(s, v+3)
		}
		if v >= len(s) || (!notAnOption(s, v) && !(j == i+2 && s[v] != '\\' && (fixedFlag(s[j:ne]) || (alwaysValued(s[j:ne]) && !optionLike(s, v))))) {
			continue
		}
		lo, hi := schemeValue(s, v)
		if live(s[lo:hi]) {
			a.hitAt("secret:flag-value", lo, hi)
		}
	}
}

func firstLine(s string, i int) string { return s[i:lineEnd(s, i)] }

// heredocFirstLine: a heredoc body's first line, without a diff row's marker (`+x = <<EOF` then `+<redacted>`, or an
// opener on a context row then an empty `+` row): the marker is the diff's, not the body's.
func heredocFirstLine(s string, lo int) string {
	line := firstLine(s, lo)
	if line != "" && (line[0] == '+' || line[0] == '-') {
		return line[1:]
	}
	return line
}

// options: the programs whose option holds a password with no name to read.
func (a *auditor) options() {
	s := a.s
	for _, po := range passwordOptions {
		for _, p := range programs(s, po.program) {
			for _, at := range commandArgs(s, p, po.program) {
				if !strings.HasPrefix(s[at:], po.option) {
					continue
				}
				k := at + len(po.option)
				v := skipBlanksConts(s, k)
				if !po.attached && v == k {
					continue
				}
				if v < len(s) && notAnOption(s, v) {
					lo, hi := crudeValue(s, v)
					if live(s[lo:hi]) {
						a.hitAt("secret:flag-value", lo, hi)
					}
				}
			}
		}
	}
	// curl's user:password: whatever follows the user's colon in its argument.
	for _, p := range programs(s, "curl") {
		for _, at := range commandArgs(s, p, "curl") {
			if s[at] != '-' {
				continue
			}
			isUser := optionWord(s, at, "--user") || optionWord(s, at, "--proxy-user") ||
				(len(s) > at+1 && (s[at+1] == 'U' || strings.Contains(strings.SplitN(s[at:], " ", 2)[0], "u")) && !strings.HasPrefix(s[at:], "--"))
			if !isUser {
				continue
			}
			ae := at
			for ae < len(s) && !isSpaceByte(s[ae]) && s[ae] != '=' {
				ae++
			}
			v := ae
			if v < len(s) && s[v] == '=' {
				v++
			} else {
				v = skipBlanksConts(s, ae)
			}
			if !strings.HasPrefix(s[at:], "--") {
				// Short options combine (`-kuadmin:x`): the user is what follows the `u`/`U` in the same word.
				for k := at + 1; k < ae; k++ {
					if s[k] == 'u' || s[k] == 'U' {
						if k+1 < ae {
							v = k + 1
						}
						break
					}
					if !isLowerASCII(s[k]) && !isUpperASCII(s[k]) {
						break
					}
				}
			}
			if v >= len(s) {
				continue
			}
			lo, hi := crudeValue(s, v)
			arg := s[lo:hi]
			if k := strings.IndexByte(arg, ':'); k >= 0 {
				// After the user's colon: one value, as the receiver splits the argument.
				w0, w1 := schemeValue(s, skipConts(s, lo+k+1))
				if live(s[w0:w1]) {
					a.hitAt("secret:flag-value", w0, w1)
				}
			}
		}
	}
	for _, m := range opensslPassRx.FindAllStringIndex(s, -1) {
		v := m[1]
		if v < len(s) && s[v] == '=' {
			v++
		} else {
			v = skipBlanksConts(s, v)
		}
		if v < len(s) && (s[v] == '"' || s[v] == '\'') {
			v++
		}
		if strings.HasPrefix(strings.ToLower(s[v:]), "pass:") {
			lo, hi := crudeValue(s, skipConts(s, v+5))
			if live(s[lo:hi]) {
				a.hitAt("secret:flag-value", lo, hi)
			}
		}
	}
	for _, m := range npmAuthRx.FindAllStringIndex(s, -1) {
		v := skipBlanksConts(s, m[1])
		if v > m[1] && v < len(s) && notAnOption(s, v) {
			lo, hi := crudeValue(s, v)
			if live(s[lo:hi]) {
				a.hitAt("secret:flag-value", lo, hi)
			}
		}
	}
}

// optionWord: the long option opt stands at i whole (`--user`, `--user=x`), not as the start of another
// (`--user-agent`).
func optionWord(s string, i int, opt string) bool {
	if !strings.HasPrefix(s[i:], opt) {
		return false
	}
	k := i + len(opt)
	return k >= len(s) || s[k] == '=' || isSpaceByte(s[k]) || s[k] == '\\' || s[k] == '"' || s[k] == '\''
}

// headers: a credential's name as a header, quoted or bare, and a scheme then an assignment.
func (a *auditor) headers() {
	s := a.s
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
			} else if e := skipBlanks(s, j); e > j {
				j = e
			} else {
				continue
			}
			var quote byte
			if j < len(s) && (s[j] == '"' || s[j] == '\'') {
				quote = s[j]
				j++
			}
			j = skipBlanks(s, j)
			for j < len(s) && s[j] == '-' {
				j++
			}
			ne := nameRunAfter(s, j)
			if ne == j || !IsCredentialName(s[j:ne]) {
				continue
			}
			c := skipBlanks(s, ne)
			if c >= len(s) || s[c] != ':' {
				continue
			}
			v := skipBlanks(s, c+1)
			var val string
			var vlo, vhi int
			if quote != 0 {
				// Closed, the value runs to its own closing quote (inside double quotes an escaped one is
				// the value's); with no closing quote on the line, to the next quote of either kind or
				// backslash, as a receiver splitting the argument reads it.
				e := v
				closed := false
				for e < len(s) && s[e] != '\n' {
					if quote == '"' && s[e] == '\\' && e+1 < len(s) {
						e += 2
						continue
					}
					if s[e] == quote {
						closed = true
						break
					}
					e++
				}
				if e > len(s) {
					e = len(s)
				}
				if !closed {
					e = v
					if v < len(s) && (s[v] == '"' || s[v] == '\'') {
						// A value that opens the other quote is that quoted part (a truncated
						// `-H 'X-Api-Key:"V"`).
						_, e = crudeValue(s, v)
					} else {
						for e < len(s) && s[e] != '"' && s[e] != '\'' && s[e] != '\\' && s[e] != '\n' {
							e++
						}
					}
				}
				val = s[v:e]
				vlo, vhi = v, e
			} else {
				lo, hi := schemeValue(s, v)
				val = s[lo:hi]
				vlo, vhi = lo, hi
				// Unquoted, the receiver's value runs to a blank: a placeholder with anything glued to it
				// (`X-Token:<redacted>,`) is a value partly sent.
				if strings.HasPrefix(val, "<redacted") && val != phRedacted && !onlyPlaceholders(val) {
					a.hitAt("secret:header", vlo, vhi)
				}
			}
			if live(val) {
				a.hitAt("secret:header", vlo, vhi)
			}
		}
	}
	low := asciiLower(s)
	for _, w := range auditSchemeWords {
		{
			for at := 0; ; {
				k := strings.Index(low[at:], w)
				if k < 0 {
					break
				}
				b := at + k
				at = b + 1
				if b > 0 && (isLowerASCII(s[b-1]) || isUpperASCII(s[b-1])) {
					continue
				}
				j := b + len(w)
				n := skipBlanks(s, j)
				if n == j {
					continue
				}
				for n < len(s) && s[n] == '-' {
					n++
				}
				ne := nameRunAfter(s, n)
				if ne == n || ne >= len(s) || (s[ne] != '=' && s[ne] != ':') || !IsCredentialName(s[n:ne]) {
					continue
				}
				lo, hi := schemeValue(s, ne+1)
				if live(s[lo:hi]) {
					a.hitAt("secret:scheme-value", lo, hi)
				}
			}
		}
	}
}

func isFixedHeader(name string) bool {
	low := strings.ToLower(name)
	for _, h := range fixedHeaders {
		if low == h {
			return true
		}
	}
	return false
}

// locateLive: the source spans of values the audit reads as sent that hold a placeholder: a
// value partly hidden. The scrubber hides them whole when it re-reads its own rendering, so
// its output passes its own audit.
func locateLive(text string) *spanSet {
	out := &spanSet{}
	found := map[string]bool{}
	for _, r := range readingsOf(rawReading(text), true) {
		sp := &spanSet{}
		a := &auditor{r: r, s: r.text, pct: r.pct, found: found, spans: sp}
		a.run()
		for _, x := range sp.spans {
			if hasPlaceholder(text[x.Lo:x.Hi]) {
				out.add(x.Lo, x.Hi, KindSecret)
			}
		}
	}
	return out
}

func hasPlaceholder(v string) bool {
	for i := 0; i < len(v); i++ {
		if placeholderAt(v, i) > 0 {
			return true
		}
	}
	return false
}

// auditSchemeWords: the words a scheme-written assignment follows (`Token password:x`), as the
// scrubber's schemeAssigned reads them.
var auditSchemeWords = []string{"bearer", "basic", "token", "digest", "negotiate", "ntlm", "apikey", "api-key"}

// code: a credential's name assigned in source: the first literal of the statement that
// still holds text, or a bare value that is not code.
func (a *auditor) code() {
	s := a.s
	for i := 0; i < len(s); i++ {
		if !isNameChar(s[i]) || (i > 0 && isNameChar(s[i-1])) {
			continue
		}
		e := nameRunAfter(s, i)
		for i < e && s[i] == '-' {
			i++
		}
		if i == e {
			i = e - 1
			continue
		}
		name := s[i:e]
		if !IsCredentialName(name) {
			i = e - 1
			continue
		}
		var v int
		if i >= 4 && strings.EqualFold(s[i-4:i], "var ") {
			v = codeOpAfter(s, e, true)
		} else {
			v = codeOpAfter(s, e, false)
		}
		if v < 0 {
			// `getenv("NAME", "x")`
			if i > 0 && (s[i-1] == '"' || s[i-1] == '\'') && e < len(s) && (s[e] == '"' || s[e] == '\'') {
				k := skipBlanks(s, e+1)
				if k < len(s) && s[k] == ',' && a.literalLive(skipBlanks(s, k+1), lineEnd(s, k)) {
					a.hit("secret:named-value")
				}
			}
			i = e - 1
			continue
		}
		if lo, hi, ok := heredocAt(s, v); ok {
			if hi > lo && live(heredocFirstLine(s, lo)) {
				a.hit("secret:named-value")
			}
			i = e - 1
			continue
		}
		w := openersEnd(s, v)
		if w < len(s) && s[w] == '[' {
			if arrayLive(s, w) {
				a.hitAt("secret:named-value", w+1, arrayBodyEnd(s, w))
			}
		} else if !isCodeValue(s, w) && !startsLiteral(s, w) && !startsPlaceholder(s, w) {
			if we := codeWordEnd(s, w); we > w && live(s[w:we]) {
				a.hitAt("secret:named-value", w, we)
			}
		}
		end := lineEnd(s, w)
		if w == end && end < len(s) {
			// a bracket or `=` at the line's end: the literal on a later line
			end = statementEnd(s, w)
		}
		if a.literalLive(w, end) {
			a.hit("secret:named-value")
		}
		i = e - 1
	}
	a.sqlAndEnv()
}

// literalLive: a literal in s[i:end] (up to 400 characters on) that holds text other than
// a placeholder.
func (a *auditor) literalLive(i, end int) bool {
	s := a.s
	if end > i+4000 {
		end = i + 4000
	}
	for i < end {
		_, open, slashes, quote, ok := literalOpen(s, i, end)
		if !ok {
			return false
		}
		cl, closing := literalEnd(s, open, slashes, quote, end)
		if closing != "" {
			body := s[open : cl-len(closing)]
			if live(body) {
				return true
			}
		}
		if cl <= open {
			cl = open + 1
		}
		i = cl
	}
	return false
}

func (a *auditor) sqlAndEnv() {
	s := a.s
	for _, m := range sqlKeyRx.FindAllStringIndex(s, -1) {
		v := m[1]
		if v < len(s) && strings.IndexByte("EeNn", s[v]) >= 0 && v+1 < len(s) && s[v+1] == '\'' {
			v++
		}
		if v < len(s) && (s[v] == '\'' || s[v] == '"') {
			lo, hi := crudeValue(s, v)
			if live(s[lo:hi]) {
				a.hit("secret:named-value")
			}
		} else if strings.HasPrefix(s[v:], "$$") {
			k := strings.Index(s[v+2:lineEnd(s, v)], "$$")
			if k > 0 && live(s[v+2:v+2+k]) {
				a.hit("secret:named-value")
			}
		}
	}
	for _, m := range identifiedByRx.FindAllStringIndex(s, -1) {
		v := m[1]
		up := strings.ToUpper(s[v:])
		if strings.HasPrefix(up, "VALUES") || strings.HasPrefix(up, "PASSWORD") {
			continue
		}
		e := v
		for e < len(s) && !isSpaceByte(s[e]) && strings.IndexByte(";'\"$", s[e]) < 0 {
			e++
		}
		if live(s[v:e]) {
			a.hit("secret:named-value")
		}
	}
	for _, m := range envRx.FindAllStringSubmatchIndex(s, -1) {
		if !IsCredentialName(s[m[2]:m[3]]) {
			continue
		}
		v := m[1]
		if v < len(s) && s[v] != '=' && live(s[v:lineEnd(s, v)]) {
			a.hit("secret:named-value")
		}
	}
}
