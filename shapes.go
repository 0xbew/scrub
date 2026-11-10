package scrub

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// --- tokens, JWTs and long random runs (R6, R7) ------------------------------------------

func (c *scan) tokens() {
	tokenSpans(c.s, func(lo, hi int) { c.hideValue(lo, hi) })
}

var jwtRx = regexp.MustCompile(`\beyJ(?:(?:\\\r?\n)*[A-Za-z0-9_\-]){5,}(?:\\\r?\n)*\.(?:(?:\\\r?\n)*[A-Za-z0-9_\-]){5,}(?:\\\r?\n)*\.(?:(?:\\\r?\n)*[A-Za-z0-9_\-]){5,}`)

// jwtGluedRx: a JWT glued to a word before it, where `\b` cannot stand; longer segments, so a word that happens
// to hold `eyJ` and two dots is not read as one.
var jwtGluedRx = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)

func (c *scan) jwt() {
	if off("jwt") {
		return
	}
	for _, m := range jwtRx.FindAllStringIndex(c.s, -1) {
		c.hide(m[0], m[1], KindJWT)
	}
	for _, m := range jwtGluedRx.FindAllStringIndex(c.s, -1) {
		c.hide(m[0], m[1], KindJWT)
	}
}

func isRunChar(ch byte) bool { return isAlnumASCII(ch) || ch == '_' || ch == '+' || ch == '/' }

// longRuns: any run of 32 or more token characters holding a letter and a digit, joined
// across continuations; kept when it is a path or an identifier written as code.
func (c *scan) longRuns() {
	if off("long") {
		return
	}
	s := c.s
	i := 0
	for i < len(s) {
		if !isRunChar(s[i]) {
			i++
			continue
		}
		start := i
		count := 0
		j := i
		var plain strings.Builder
		for j < len(s) {
			if isRunChar(s[j]) {
				plain.WriteByte(s[j])
				count++
				j++
				continue
			}
			if n := contAt(s, j); n > 0 {
				k := skipConts(s, j)
				if k < len(s) && isRunChar(s[k]) {
					j = k
					continue
				}
			}
			break
		}
		end := j
		eq := 0
		for end < len(s) && s[end] == '=' && eq < 2 {
			end++
			eq++
		}
		i = j
		if count < 32 {
			continue
		}
		body := plain.String()
		if !hasDigitAndAlphaASCII(body) {
			continue
		}
		token := s[start:end]
		if IsIdentifier(token) && writtenAsCode(s, start, end) {
			continue
		}
		after := byte(0)
		if end < len(s) {
			after = s[end]
		}
		trim := strings.Trim(body, "/")
		if eq == 0 && (after == '.' || after == '-') && strings.Contains(trim, "/") && !strings.Contains(body, "+") &&
			!strings.Contains(token, "\\") && wordlike(body, isPathSep) {
			continue
		}
		c.hide(start, end, KindLong)
	}
}

// hasLongRun: the long-run rule fires somewhere in a reading (the audit's check; it shares
// the classifier, so a value the scrubber keeps as a path or as code passes).
func hasLongRun(r *reading) bool {
	sp := &spanSet{}
	c := &scan{s: r.text, r: r, out: sp}
	c.longRuns()
	for _, x := range sp.spans {
		if !onlyPlaceholders(r.src[x.Lo:x.Hi]) {
			return true
		}
	}
	return false
}

func hasDigitAndAlphaASCII(s string) bool {
	d, a := false, false
	for i := 0; i < len(s); i++ {
		if isDigitASCII(s[i]) {
			d = true
		} else if isLowerASCII(s[i]) || isUpperASCII(s[i]) {
			a = true
		}
	}
	return d && a
}

// --- email and phone (R8) ----------------------------------------------------------------

func isLocalChar(s string, i int) bool {
	ch := s[i]
	return ch == '.' || ch == '+' || ch == '-' || isWordAt(s, i)
}

func isDomainChar(s string, i int) bool { return s[i] == '-' || isWordAt(s, i) }

// emails: every address shape. The last label is letters (`lodash@4.17.21` is no address);
// a local part of punctuation alone counts except at a line start (`+@pytest.mark.x`).
func emails(s string, emit func(lo, hi int)) {
	if off("email") {
		return
	}
	for at := strings.IndexByte(s, '@'); at >= 0; at = nextByte(s, '@', at+1) {
		l := at
		for l > 0 && isLocalChar(s, l-1) {
			l--
		}
		// back up over a partial rune
		if l == at {
			continue
		}
		local := s[l:at]
		hasWord := false
		for i := l; i < at; i++ {
			if isWordAt(s, i) {
				hasWord = true
				break
			}
		}
		if !hasWord && (l == 0 || s[l-1] == '\n') {
			continue
		}
		_ = local
		// domain labels
		j := at + 1
		var dots []int
		labelStart := j
		for j < len(s) && isDomainChar(s, j) {
			j++
		}
		if j == labelStart {
			continue
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
		for d := len(dots) - 1; d >= 0; d-- {
			ls := dots[d] + 1
			le := ls
			for le < len(s) && (isLowerASCII(s[le]) || isUpperASCII(s[le])) {
				le++
			}
			if le-ls < 2 {
				continue
			}
			// An underscore glued to the last label (`a@b.test_` in a name) does not make it a longer label.
			if le < len(s) && isDomainChar(s, le) && s[le] != '_' {
				continue
			}
			emit(l, le)
			break
		}
	}
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
	return !(ch == '.' || ch == '+' || ch == '-' || wordBefore(s, i))
}

func phoneBoundaryAfter(s string, i int) bool {
	return i >= len(s) || !(s[i] == '-' || isWordAt(s, i))
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
	var ends []int
	for _, a := range starts {
		if a == i && i < len(s) && s[i] == '+' {
			continue
		}
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
		for _, b := range bs {
			if k, ok := digitsAt(s, b, 3); ok {
				if k2, ok := sepAt(s, k); ok {
					if k3, ok := digitsAt(s, k2, 4); ok {
						ends = append(ends, k3)
					}
				}
			}
		}
	}
	return ends
}

func phonesNANP(s string, emit func(lo, hi int)) {
	if off("phone") {
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
	if off("phone") {
		return
	}
	for i := strings.IndexByte(s, '+'); i >= 0; i = nextByte(s, '+', i+1) {
		if !phoneBoundaryBefore(s, i) || i+1 >= len(s) || s[i+1] < '1' || s[i+1] > '9' {
			continue
		}
		// candidate ends: after k class characters (6..22) then a digit
		var pos []int // byte offset after each class rune
		j := i + 2
		for n := 0; n < 23 && j < len(s); n++ {
			r, sz := utf8.DecodeRuneInString(s[j:])
			if !(isPyDigit(r) || isPySpace(r) || r == '(' || r == ')' || r == '.' || r == '-') {
				break
			}
			j += sz
			pos = append(pos, j)
		}
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
			if digits >= 8 {
				emit(i, e)
			}
			break
		}
	}
}

// shapes: addresses and phone numbers. A percent-decoded reading reads `+` as a space, which
// makes a diff's `+` row marker or a URL's `a+b` into a phone's spacing: phones are not read
// there.
func (c *scan) shapes() {
	emails(c.s, func(lo, hi int) { c.hide(lo, hi, KindEmail) })
	if c.r.pctd {
		return
	}
	// Phones as the text is written (a row's `+` then digits reads as an international number,
	// as Python's scrub() reads it), and as the audit reads them: a diff hunk's sides apart,
	// markers stripped, so a context row's ` +44 ...` is read as its file holds it.
	phonesIntl(c.s, func(lo, hi int) { c.hide(lo, hi, KindPhone) })
	phonesNANP(c.s, func(lo, hi int) { c.hide(lo, hi, KindPhone) })
	for _, pr := range phoneReadings(c.s) {
		pc := &scan{s: pr.text, r: composeReadings(c.r, pr), out: c.out}
		phonesIntl(pc.s, func(lo, hi int) { pc.hide(lo, hi, KindPhone) })
		phonesNANP(pc.s, func(lo, hi int) { pc.hide(lo, hi, KindPhone) })
	}
}

// composeReadings: inner's bytes (offsets into outer's text) mapped through outer to its source.
func composeReadings(outer, inner *reading) *reading {
	r := &reading{text: inner.text, lo: make([]int32, len(inner.lo)), hi: make([]int32, len(inner.hi)), src: outer.src,
		kind: outer.kind, pct: outer.pct, pctd: outer.pctd, joined: outer.joined}
	for i := range inner.lo {
		lo, hi := outer.source(int(inner.lo[i]), int(inner.hi[i]))
		r.lo[i], r.hi[i] = int32(lo), int32(hi)
	}
	return r
}

func hasEmail(s string) bool {
	found := false
	emails(s, func(lo, hi int) { found = true })
	return found
}

func hasPhoneShape(s string) bool {
	found := false
	phonesIntl(s, func(lo, hi int) { found = true })
	phonesNANP(s, func(lo, hi int) { found = true })
	return found
}
