package detect

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0xbew/scrub/internal/gate"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
)

// --- email and phone (R8) ----------------------------------------------------------------

func isLocalChar(s string, i int) bool {
	ch := s[i]
	return ch == '.' || ch == '+' || ch == '-' || lex.IsWordAt(s, i)
}

func isDomainChar(s string, i int) bool { return s[i] == '-' || lex.IsWordAt(s, i) }

// Emails: every address shape. The last label is letters (`lodash@4.17.21` is no address);
// a local part of punctuation alone counts except at a line start (`+@pytest.mark.x`).
func Emails(s string, emit func(lo, hi int)) {
	if gate.Off(gate.Email) {
		return
	}
	for at := strings.IndexByte(s, '@'); at >= 0; at = lex.NextByte(s, '@', at+1) {
		l, ok := emailLocalStart(s, at)
		if !ok {
			continue
		}
		dots, ok := emailDots(s, at)
		if !ok {
			continue
		}
		if le, ok := emailLastLabelEnd(s, dots); ok {
			emit(l, le)
		}
	}
}

// emailLocalStart: where the local part before the `@` at at starts; false when it is empty, or
// punctuation alone at a line's start.
func emailLocalStart(s string, at int) (int, bool) {
	l := at
	for l > 0 && isLocalChar(s, l-1) {
		l--
	}
	// back up over a partial rune
	if l == at {
		return 0, false
	}
	local := s[l:at]
	hasWord := false
	for i := l; i < at; i++ {
		if lex.IsWordAt(s, i) {
			hasWord = true
			break
		}
	}
	if !hasWord && (l == 0 || s[l-1] == '\n') {
		return 0, false
	}
	_ = local
	return l, true
}

// emailDots: the dot before each label of the domain after the `@` at at; false when no label
// follows the `@`.
func emailDots(s string, at int) ([]int, bool) {
	// domain labels
	j := at + 1
	var dots []int
	labelStart := j
	for j < len(s) && isDomainChar(s, j) {
		j++
	}
	if j == labelStart {
		return nil, false
	}
	for j < len(s) && s[j] == '.' {
		k := j + 1
		for k < len(s) && isDomainChar(s, k) {
			k++
		}
		if k == j+1 {
			break
		}
		dots = append(dots, j)
		j = k
	}
	return dots, true
}

// emailLastLabelEnd: the end of the address: the last label after a dot, from the right, that
// starts with two letters or more and is not glued to more of a domain.
func emailLastLabelEnd(s string, dots []int) (int, bool) {
	for _, dot := range slices.Backward(dots) {
		ls := dot + 1
		le := ls
		for le < len(s) && (lex.IsLowerASCII(s[le]) || lex.IsUpperASCII(s[le])) {
			le++
		}
		if le-ls < 2 {
			continue
		}
		// An underscore glued to the last label (`a@b.test_` in a name) does not make it a longer label.
		if le < len(s) && isDomainChar(s, le) && s[le] != '_' {
			continue
		}
		return le, true
	}
	return 0, false
}

func isPyDigit(r rune) bool { return unicode.IsDigit(r) }

func isPySpace(r rune) bool {
	return unicode.IsSpace(r) || r == '\x1c' || r == '\x1d' || r == '\x1e' || r == '\x1f' || r == '\x85'
}

// phoneBoundaryBefore: `(?<![\w.+-])`.
func phoneBoundaryBefore(s string, i int) bool {
	if i == 0 {
		return true
	}
	ch := s[i-1]
	return !(ch == '.' || ch == '+' || ch == '-' || lex.WordBefore(s, i))
}

func phoneBoundaryAfter(s string, i int) bool {
	return i >= len(s) || !(s[i] == '-' || lex.IsWordAt(s, i))
}

// digitsAt reads exactly n digits at i.
func digitsAt(s string, i, n int) (int, bool) {
	for k := 0; k < n; k++ {
		if i >= len(s) {
			return i, false
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		if !isPyDigit(r) {
			return i, false
		}
		i += sz
	}
	return i, true
}

func sepAt(s string, i int) (int, bool) {
	if i >= len(s) {
		return i, false
	}
	if s[i] == '.' || s[i] == '-' {
		return i + 1, true
	}
	r, sz := utf8.DecodeRuneInString(s[i:])
	if isPySpace(r) {
		return i + sz, true
	}
	return i, false
}

// nanpAt: `(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}` at i, every end.
func nanpAt(s string, i int) []int {
	starts := nanpStarts(s, i)
	var ends []int
	for _, a := range starts {
		if a == i && i < len(s) && s[i] == '+' {
			continue
		}
		bs := nanpAreaEnds(s, a)
		ends = nanpLineEnds(s, bs, ends)
	}
	return ends
}

// nanpStarts: where the area code may start after the optional `+1` and separator at i.
func nanpStarts(s string, i int) []int {
	var starts []int
	starts = append(starts, i)
	j := i
	if j < len(s) && s[j] == '+' {
		j++
	}
	if j < len(s) && s[j] == '1' {
		k := j + 1
		starts = append(starts, k)
		if k2, ok := sepAt(s, k); ok {
			starts = append(starts, k2)
		}
	}
	return starts
}

// nanpAreaEnds: every end of an area code at a: `(\d{3})` with an optional space after, or
// `\d{3}` and a separator.
func nanpAreaEnds(s string, a int) []int {
	var bs []int
	if a < len(s) && s[a] == '(' {
		if k, ok := digitsAt(s, a+1, 3); ok && k < len(s) && s[k] == ')' {
			bs = append(bs, k+1)
			if k2 := k + 1; k2 < len(s) {
				r, sz := utf8.DecodeRuneInString(s[k2:])
				if isPySpace(r) {
					bs = append(bs, k2+sz)
				}
			}
		}
	} else if k, ok := digitsAt(s, a, 3); ok {
		if k2, ok := sepAt(s, k); ok {
			bs = append(bs, k2)
		}
	}
	return bs
}

// nanpLineEnds: ends with the end of `\d{3}[\s.-]\d{4}` after each area code's end in bs
// appended.
func nanpLineEnds(s string, bs, ends []int) []int {
	for _, b := range bs {
		if k, ok := digitsAt(s, b, 3); ok {
			if k2, ok := sepAt(s, k); ok {
				if k3, ok := digitsAt(s, k2, 4); ok {
					ends = append(ends, k3)
				}
			}
		}
	}
	return ends
}

func phonesNANP(s string, emit func(lo, hi int)) {
	if gate.Off(gate.Phone) {
		return
	}
	for i := 0; i < len(s); {
		ch := s[i]
		if !(ch == '+' || ch == '(' || ch == '1' || (ch >= '0' && ch <= '9') || ch >= 0x80) {
			i++
			continue
		}
		if !phoneBoundaryBefore(s, i) {
			i++
			continue
		}
		matched := false
		for _, e := range nanpAt(s, i) {
			if phoneBoundaryAfter(s, e) {
				emit(i, e)
				i = e
				matched = true
				break
			}
		}
		if !matched {
			i++
		}
	}
}

// phonesIntl: `\+[1-9][\d\s().-]{6,22}\d` with 8 or more digits.
func phonesIntl(s string, emit func(lo, hi int)) {
	if gate.Off(gate.Phone) {
		return
	}
	for i := strings.IndexByte(s, '+'); i >= 0; i = lex.NextByte(s, '+', i+1) {
		if !phoneBoundaryBefore(s, i) || i+1 >= len(s) || s[i+1] < '1' || s[i+1] > '9' {
			continue
		}
		if e, ok := intlPhoneEnd(s, i, phoneClassEnds(s, i+2)); ok {
			emit(i, e)
		}
	}
}

// phoneClassEnds: the byte offset after each of up to 23 phone characters (`[\d\s().-]`) from j.
func phoneClassEnds(s string, j int) []int {
	var pos []int
	for n := 0; n < 23 && j < len(s); n++ {
		r, sz := utf8.DecodeRuneInString(s[j:])
		if !isPhoneClass(r) {
			break
		}
		j += sz
		pos = append(pos, j)
	}
	return pos
}

func isPhoneClass(r rune) bool {
	return isPyDigit(r) || isPySpace(r) || r == '(' || r == ')' || r == '.' || r == '-'
}

// intlPhoneEnd: the longest candidate end in pos (6 to 22 phone characters then a digit) with a boundary after
// it; ok when the number from i to there holds 8 or more digits. A shorter candidate is never tried after it.
func intlPhoneEnd(s string, i int, pos []int) (int, bool) {
	for n := len(pos); n >= 7; n-- {
		e := pos[n-1]
		r, _ := utf8.DecodeLastRuneInString(s[:e])
		if !isPyDigit(r) || n-1 > 22 || n-1 < 6 {
			continue
		}
		if !phoneBoundaryAfter(s, e) {
			continue
		}
		digits := 0
		for _, r := range s[i:e] {
			if isPyDigit(r) {
				digits++
			}
		}
		return e, digits >= 8
	}
	return 0, false
}

// Shapes: addresses and phone numbers. A percent-decoded reading reads `+` as a space, which
// makes a diff's `+` row marker or a URL's `a+b` into a phone's spacing: phones are not read
// there.
func (c *Scan) Shapes() {
	Emails(c.S, func(lo, hi int) { c.Hide(lo, hi, span.KindEmail) })
	if c.R.Pctd {
		return
	}
	// Phones as the text is written (a row's `+` then digits reads as an international number,
	// as Python's scrub() reads it), and as the audit reads them: a diff hunk's sides apart,
	// markers stripped, so a context row's ` +44 ...` is read as its file holds it.
	phonesIntl(c.S, func(lo, hi int) { c.Hide(lo, hi, span.KindPhone) })
	phonesNANP(c.S, func(lo, hi int) { c.Hide(lo, hi, span.KindPhone) })
	for _, pr := range reading.PhoneReadings(c.S) {
		pc := &Scan{S: pr.Text, R: composeReadings(c.R, pr), Out: c.Out}
		phonesIntl(pc.S, func(lo, hi int) { pc.Hide(lo, hi, span.KindPhone) })
		phonesNANP(pc.S, func(lo, hi int) { pc.Hide(lo, hi, span.KindPhone) })
	}
}

// composeReadings: inner's bytes (offsets into outer's text) mapped through outer to its source.
func composeReadings(outer, inner *reading.Reading) *reading.Reading {
	r := &reading.Reading{Text: inner.Text, Lo: make([]int32, len(inner.Lo)), Hi: make([]int32, len(inner.Hi)), Src: outer.Src,
		Kind: outer.Kind, Pct: outer.Pct, Pctd: outer.Pctd, Joined: outer.Joined}
	for i := range inner.Lo {
		lo, hi := outer.Source(int(inner.Lo[i]), int(inner.Hi[i]))
		r.Lo[i], r.Hi[i] = int32(lo), int32(hi)
	}
	return r
}

func HasEmail(s string) bool {
	found := false
	Emails(s, func(lo, hi int) { found = true })
	return found
}

func HasPhoneShape(s string) bool {
	found := false
	phonesIntl(s, func(lo, hi int) { found = true })
	phonesNANP(s, func(lo, hi int) { found = true })
	return found
}
