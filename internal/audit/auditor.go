package audit

import (
	"strings"

	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
	"github.com/0xbew/scrub/internal/vocab"
)

type auditor struct {
	r     *reading.Reading
	s     string
	pct   bool
	found map[string]bool
	spans *span.Set // set when locating
}

func (a *auditor) hit(rule string) { a.found[rule] = true }

// hitAt: a hit whose value is s[lo:hi]; when the auditor locates, the value's source span is
// kept, so the scrubber can hide what its own audit still reads as sent (see locateLive).
func (a *auditor) hitAt(rule string, lo, hi int) {
	a.hit(rule)
	if a.spans != nil && lo < hi {
		slo, shi := a.r.Source(lo, hi)
		a.spans.Add(slo, shi, span.KindSecret)
	}
}

// live: a value that still holds something other than placeholders, quotes and escapes.
func live(v string) bool {
	t := strings.Trim(v, " \t\r\n\"'`\\,;")
	if t == "" {
		return false
	}
	return !lex.OnlyPlaceholders(t)
}

// schemeWord: a value that opens with an auth scheme takes the word after it too.
func schemeValue(s string, i int) (int, int) {
	w := i
	for w < len(s) && lex.IsAlnumASCII(s[w]) {
		w++
	}
	if w > i && lex.AuthSchemes[strings.ToLower(s[i:w])] {
		k := lex.SkipBlanks(s, w)
		if k > w && k < len(s) {
			_, e := lex.CrudeValue(s, k)
			return i, e
		}
	}
	return lex.CrudeValue(s, i)
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

// heredocValues: a heredoc opening a credential's value whose body holds more than placeholders (internal/detect's
// heredocValues, the shape the scrubber hides).
func (a *auditor) heredocValues() {
	detect.HeredocValues(a.s, func(lo, hi int) {
		if live(a.s[lo:hi]) {
			a.hit("secret:named-value")
		}
	})
}

// assignments: any name, `=`, a value.
func (a *auditor) assignments() {
	s := a.s
	for p := strings.IndexByte(s, '='); p >= 0; p = lex.NextByte(s, '=', p+1) {
		q := lex.NameRunBefore(s, p)
		var name string
		switch {
		case q < p:
			name = lex.TrimDashes(s[q:p])
		case p > 0 && (s[p-1] == '"' || s[p-1] == '\''):
			e := p - 1
			for e > 0 && s[e-1] == '\\' {
				e--
			}
			q2 := lex.NameRunBefore(s, e)
			if q2 == e {
				continue
			}
			name = lex.TrimDashes(s[q2:e])
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
		if q < p && vocab.IsCredentialName(name) {
			if e := receiverValueEnd(s, p+1); strings.Trim(s[p+1:e], "\"'") != "" && strings.Trim(s[p+1:e], "\"'") != lex.PhRedacted {
				a.hitAt("secret:named-value", p+1, e)
			} else if e == p+1 {
				// Nothing glued to `NAME=`: the receiver reads on past blanks and line breaks to a quoted string,
				// which is the value when the scrubber hid part of it (`NAME=` then `"echo <redacted>"`).
				w := p + 1
				for w < len(s) && lex.IsSpaceByte(s[w]) {
					w++
				}
				if w > p+1 && w < len(s) && (s[w] == '"' || s[w] == '\'') {
					e := receiverValueEnd(s, w)
					if v := strings.Trim(s[w:e], "\"'"); strings.Contains(v, "<redacted") && v != lex.PhRedacted {
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
		if vocab.IsCredentialName(name) || (detect.HasKeyword(name) && vocab.LooksSecret(v)) {
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
	q := lex.NameRunBefore(s, e)
	if q == e || !vocab.IsCredentialName(lex.TrimDashes(s[q:e])) || (p+1 < len(s) && s[p+1] == '=') || (e > 0 && strings.IndexByte("!<>=", s[e-1]) >= 0) {
		return
	}
	v := lex.SkipBlanks(s, p+1)
	if v == p+1 || v >= len(s) {
		return
	}
	end := v
	for end < len(s) && !lex.IsSpaceByte(s[end]) && s[end] != '"' && s[end] != '\'' && s[end] != '`' {
		end++
	}
	// What closes the statement around it (`)` `,` `;` `]` `}`) and a trailing escape are not the value's.
	val := strings.TrimRight(s[v:end], "\\),;]}")
	if strings.HasPrefix(val, "<redacted") && val != lex.PhRedacted {
		a.hitAt("secret:named-value", v, end)
	}
}

// colons: `"name": value` anywhere, `name: value` first on a line or after `{` `,`.
func (a *auditor) colons() {
	s := a.s
	for p := strings.IndexByte(s, ':'); p >= 0; p = lex.NextByte(s, ':', p+1) {
		e := p
		for e > 0 && lex.IsSpaceByte(s[e-1]) {
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
		q := lex.NameRunBefore(s, ne)
		if q == ne {
			continue
		}
		name := lex.TrimDashes(s[q:ne])
		v := lex.SkipSpaceConts(s, p+1)
		if quoted && q > 0 && (s[q-1] == '"' || s[q-1] == '\'') {
			if v < len(s) && (s[v] == '"' || s[v] == '\'') {
				lo, hi := v, a.r.QuotedEnd(s, v, func(s string, i int) int { _, e := lex.CrudeValue(s, i); return e })
				val := s[lo:hi]
				// The value to its quote: anything but `<redacted>` is a value (a placeholder and a
				// blank too), as Python's audit reads a field.
				inner := strings.TrimRight(s[lo+1:hi], s[lo:lo+1])
				if inner != "" && inner != lex.PhRedacted && (vocab.IsCredentialName(name) || (detect.HasKeyword(name) && looksSecretOrFirstWord(val))) {
					a.hitAt("secret:json-field", lo, hi)
				}
			}
			if v < len(s) && s[v] == '[' && !a.pct && vocab.IsCredentialName(name) && arrayLive(s, v) {
				a.hitAt("secret:json-field", v+1, arrayBodyEnd(s, v))
			}
			continue
		}
		if !vocab.IsCredentialName(name) {
			continue
		}
		if v < len(s) && s[v] == '[' && !a.pct && arrayLive(s, v) {
			a.hitAt("secret:json-field", v+1, arrayBodyEnd(s, v))
		}
		ls := lex.LineStart(s, q)
		head := strings.Trim(s[ls:q], " \t+-") == ""
		j := q
		for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '+' || s[j-1] == '-') {
			j--
		}
		flow := j > 0 && (s[j-1] == '{' || s[j-1] == ',')
		if !head && !flow {
			continue
		}
		w := lex.SkipBlanks(s, p+1)
		if head && !flow && w == p+1 {
			continue
		}
		if w >= len(s) || s[w] == '{' || detect.IsTypeWord(s, w) {
			continue
		}
		if detect.IsBlockIndicator(s, w) {
			if !a.pct && blockLive(s, w) {
				a.hit("secret:colon-value")
			}
			continue
		}
		// A known header's value in an object literal runs to the line end (its own `, k=v`).
		if flow && isFixedHeader(name) {
			if le := detect.ContLineEnd(s, w); live(s[w:le]) {
				a.hitAt("secret:colon-value", w, le)
			}
			continue
		}
		// a value, then every word after a blank that is not a stop word
		end := auditWordEnd(s, w, true)
		for {
			k := lex.SkipBlanks(s, end)
			if k == end || k >= len(s) || detect.ColonStop(s, k) {
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
		_, e := lex.CrudeValue(s, i)
		return e
	}
	j := i
	for j < len(s) && !lex.IsSpaceByte(s[j]) && strings.IndexByte("\"',;}]", s[j]) < 0 {
		j++
	}
	if first && lex.AuthSchemes[strings.ToLower(s[i:j])] {
		k := lex.SkipBlanks(s, j)
		if k > j && k < len(s) {
			e := k
			for e < len(s) && !lex.IsSpaceByte(s[e]) && strings.IndexByte("\"',;}]", s[e]) < 0 {
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
func arrayBodyEnd(s string, v int) int { return detect.ArrayEnd(s, v) }

func arrayLive(s string, v int) bool {
	end := len(s)
	if k := strings.IndexByte(s[v:], ']'); k >= 0 {
		end = v + k
	}
	if end-v > 4000 {
		end = v + 4000
	}
	// The array to its first `]`, and to the `]` that closes it with strings skipped.
	return arrayLiveTo(s, v, end) || arrayLiveTo(s, v, detect.ArrayEnd(s, v))
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
	le := lex.LineEnd(s, w)
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
	key := indent(lex.LineStart(s, w))
	for i := le + 1; i < len(s); {
		e := lex.LineEnd(s, i)
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
