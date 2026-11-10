package scrub

import (
	"strings"
	"unicode/utf8"
)

// A reading is a decoded view of a source text. Every byte of the reading knows the source
// span it came from, so a value found in a reading hides its source bytes, decoding and all.
type reading struct {
	text string
	lo   []int32 // lo[i], hi[i]: the source span byte i of text came from
	hi   []int32
	kind readingKind
	pct  bool // percent-decoded somewhere along the way, `+` read as a space
	// pctd: percent-decoded somewhere along the way, `+` kept or not (pct is the stricter case).
	pctd bool
	// joined: an escaped `\n` `\r` `\t` was read as its letter, so the words either side of it
	// run together: shapes and long runs are not read here (the json reading has them apart).
	joined bool
	src    string // the source text the offsets point into
}

type readingKind uint8

const (
	readRaw readingKind = iota
	readUnescaped
	readPercent
	readDecoded // HTML entities, fullwidth folded, continuations joined
)

// maxEscapeLevels: how many levels of backslash escaping the readings undo.
const maxEscapeLevels = 8

func rawReading(s string) *reading {
	r := &reading{text: s, lo: make([]int32, len(s)), hi: make([]int32, len(s)), kind: readRaw, src: s}
	for i := range s {
		r.lo[i], r.hi[i] = int32(i), int32(i+1)
	}
	// range over a string steps by rune; fill the continuation bytes too.
	for i := 0; i < len(s); i++ {
		r.lo[i], r.hi[i] = int32(i), int32(i+1)
	}
	return r
}

// sameForm: the bytes at i and j were written the same way in the source (`"` and `"`, `%22`
// and `%22`, `\"` and `\"`). A value's closing quote is one written as its opening quote.
func (r *reading) sameForm(i, j int) bool {
	if r == nil || r.src == "" || i < 0 || j < 0 || i >= len(r.lo) || j >= len(r.lo) {
		return true
	}
	return r.src[r.lo[i]:r.hi[i]] == r.src[r.lo[j]:r.hi[j]]
}

// quoteFormEnd: a quoted value opening at i whose scan (end) stopped on a quote written
// another way (a raw `"` inside a `%22...%22` value) reads on, past each such quote, to one
// written as the opener, or to where next stops.
func (r *reading) quoteFormEnd(s string, i, end int, next func(s string, i int) int) int {
	for end > i+1 && end <= len(s) && s[end-1] == s[i] && !r.sameForm(i, end-1) {
		e := next(s, end-1)
		if e <= end {
			break
		}
		end = e
	}
	return end
}

// contBreak: the line break at i was written escaped (`\` then the break): inside a quoted
// value it is a continuation, and the value reads on past it.
func (r *reading) contBreak(i int) bool {
	if r == nil || r.src == "" || i >= len(r.lo) {
		return false
	}
	lo, hi := int(r.lo[i]), int(r.hi[i])
	return hi-lo >= 2 && r.src[lo] == '\\'
}

// quotedEnd: a quoted value opening at i, as next scans it, read on past a quote written
// another way than the opener and past a continued line break.
func (r *reading) quotedEnd(s string, i int, next func(s string, i int) int) int {
	end := next(s, i)
	for {
		end = r.quoteFormEnd(s, i, end, next)
		if end < len(s) && s[end] == '\n' && r.contBreak(end) {
			if e := next(s, end); e > end {
				end = e
				continue
			}
		}
		return end
	}
}

// source maps a reading span [a, b) to the source span it covers.
func (r *reading) source(a, b int) (int, int) {
	if a >= b {
		return 0, 0
	}
	lo, hi := int(r.lo[a]), int(r.hi[b-1])
	for i := a; i < b; i++ {
		if int(r.lo[i]) < lo {
			lo = int(r.lo[i])
		}
		if int(r.hi[i]) > hi {
			hi = int(r.hi[i])
		}
	}
	return lo, hi
}

// unescape removes one level of backslash escaping: `\x` becomes `x`, and `x` maps to the
// backslash and itself. A trailing lone backslash stays. With json, the level is read as a
// JSON string's: `\n` `\r` `\t` are line breaks and tabs and `\u00XX` is its character, so a
// line-start rule sees the line a serialized text starts. Without it, `\n` reads as `n`, and
// the reading is marked joined: words either side of it run together.
func (r *reading) unescape(json bool) *reading {
	s := r.text
	out := &reading{kind: readUnescaped, pct: r.pct, pctd: r.pctd, src: r.src, joined: r.joined}
	b := make([]byte, 0, len(s))
	emit := func(c byte, lo, hi int32) {
		b = append(b, c)
		out.lo = append(out.lo, lo)
		out.hi = append(out.hi, hi)
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n', 'r', 't':
				if json {
					c := byte('\n')
					if s[i+1] == 'r' {
						c = '\r'
					} else if s[i+1] == 't' {
						c = '\t'
					}
					emit(c, r.lo[i], r.hi[i+1])
					i++
					continue
				}
				out.joined = true
			case 'u':
				if json {
					if c, n := unicodeEscape(s, i); n > 0 {
						var buf [4]byte
						for _, b := range buf[:utf8.EncodeRune(buf[:], c)] {
							emit(b, r.lo[i], r.hi[i+n-1])
						}
						i += n - 1
						continue
					}
				}
			case 'x':
				if json && i+3 < len(s) {
					h, ok1 := unhex(s[i+2])
					l, ok2 := unhex(s[i+3])
					if ok1 && ok2 {
						emit(h<<4|l, r.lo[i], r.hi[i+3])
						i += 3
						continue
					}
				}
			case '0', '1', '2', '3', '4', '5', '6', '7':
				if json {
					v, n := 0, 0
					for n < 3 && i+1+n < len(s) && s[i+1+n] >= '0' && s[i+1+n] <= '7' {
						v = v*8 + int(s[i+1+n]-'0')
						n++
					}
					if v <= 0xFF {
						emit(byte(v), r.lo[i], r.hi[i+n])
						i += n
						continue
					}
				}
			}
			// The escaped character: one whole rune.
			j := i + 1
			k := j + 1
			for k < len(s) && s[k]&0xC0 == 0x80 {
				k++
			}
			for m := j; m < k; m++ {
				emit(s[m], r.lo[i], r.hi[m])
			}
			i = k - 1
			continue
		}
		emit(s[i], r.lo[i], r.hi[i])
	}
	out.text = string(b)
	return out
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// unicodeEscape: the character a `\uXXXX` escape at i stands for (a surrogate pair's two escapes as one), and
// how many bytes it spans; 0 when it is not one.
func unicodeEscape(s string, i int) (rune, int) {
	hex4 := func(j int) (rune, bool) {
		if j+6 > len(s) || s[j] != '\\' || s[j+1] != 'u' {
			return 0, false
		}
		var v rune
		for k := j + 2; k < j+6; k++ {
			h, ok := unhex(s[k])
			if !ok {
				return 0, false
			}
			v = v<<4 | rune(h)
		}
		return v, true
	}
	c, ok := hex4(i)
	if !ok {
		return 0, 0
	}
	if c >= 0xD800 && c < 0xDC00 {
		if lo, ok := hex4(i + 6); ok && lo >= 0xDC00 && lo < 0xE000 {
			return 0x10000 + (c-0xD800)<<10 + (lo - 0xDC00), 12
		}
		return 0, 0
	}
	if c >= 0xDC00 && c < 0xE000 {
		return 0, 0
	}
	return c, 6
}

// percentDecode reads `%XX` as its byte and `+` as a space, as a URL's receiver does.
func (r *reading) percentDecode() *reading { return r.percentDecodeAs(true) }

// percentDecodeAs reads `%XX` as its byte; with plus, `+` as a space too (a form body or a query), without it
// `+` stays (a path, or text that only escapes some bytes).
func (r *reading) percentDecodeAs(plus bool) *reading {
	s := r.text
	out := &reading{kind: readPercent, pct: plus || r.pct, pctd: true, src: r.src}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b = append(b, h<<4|l)
				out.lo = append(out.lo, r.lo[i])
				out.hi = append(out.hi, r.hi[i+2])
				i += 2
				continue
			}
		}
		c := s[i]
		if c == '+' && plus {
			c = ' '
		}
		b = append(b, c)
		out.lo = append(out.lo, r.lo[i])
		out.hi = append(out.hi, r.hi[i])
	}
	out.text = string(b)
	return out
}

// readings: the text as written, each level of backslash escaping removed, and the same decoded (when decode is
// set): percent-decoded (`+` kept, and `+` as a space), HTML entities, fullwidth letters folded, continuations
// joined, and up to two of these in turn (`%2522` is `%22` is `"`). Each level that holds a JSON string's escapes
// is also read as one (not read further down). Duplicates are dropped.
func readingsOf(base *reading, decode bool) []*reading {
	seen := map[string]bool{base.text: true}
	out := []*reading{base}
	starts := []*reading{base}
	if decode {
		frontier := []*reading{base}
		// A continuation is joined first, as a shell joins it before anything decodes what it wrote; the two
		// decodings after it may then read an escape the continuation split (`%25` `\`-newline `20`).
		if strings.Contains(base.text, "\\\n") || strings.Contains(base.text, "\\\r\n") {
			j := base.joinConts()
			if !seen[j.text] {
				seen[j.text] = true
				starts = append(starts, j)
				frontier = append(frontier, j)
			}
		}
		for depth := 0; depth < 2 && len(frontier) > 0; depth++ {
			var next []*reading
			for _, r := range frontier {
				for _, d := range r.decodings() {
					if !seen[d.text] {
						seen[d.text] = true
						starts = append(starts, d)
						next = append(next, d)
					}
				}
			}
			frontier = next
		}
	}
	add := func(r *reading) {
		if !seen[r.text] {
			seen[r.text] = true
			out = append(out, r)
		}
	}
	for si, start := range starts {
		level := start
		if si > 0 {
			out = append(out, level)
		}
		for n := 0; n < maxEscapeLevels; n++ {
			if hasJSONEscape(level.text) {
				add(level.unescape(true))
			}
			next := level.unescape(false)
			if next.text == level.text {
				break
			}
			level = next
			add(level)
		}
	}
	return out
}

// decodings: each decoding a receiver may apply to r that changes it.
func (r *reading) decodings() []*reading {
	var out []*reading
	s := r.text
	if strings.IndexByte(s, '%') >= 0 {
		if p := r.percentDecodeAs(false); p.text != s {
			out = append(out, p)
		}
	}
	// A form body reads `+` as a space even where nothing is percent-encoded.
	if strings.IndexByte(s, '+') >= 0 {
		if p := r.percentDecodeAs(true); p.text != s {
			out = append(out, p)
		}
	}
	if strings.IndexByte(s, '&') >= 0 {
		if h := r.htmlDecode(); h.text != s {
			out = append(out, h)
		}
	}
	if strings.Contains(s, "\xef\xbc") || strings.Contains(s, "\xef\xbd") || strings.Contains(s, "\xe3\x80\x80") {
		out = append(out, r.foldWidth())
	}
	// Not after `+` was read as a space: a diff row's marker is gone there, and its rows would run together.
	if !r.pct && (strings.Contains(s, "\\\n") || strings.Contains(s, "\\\r\n")) {
		out = append(out, r.joinConts())
	}
	return out
}

// derived: a reading built byte by byte from r, each byte mapped through r to the source.
type derived struct {
	r   *reading
	out *reading
	b   []byte
}

func (r *reading) derive(kind readingKind) *derived {
	return &derived{r: r, out: &reading{kind: kind, pct: r.pct, pctd: r.pctd, joined: r.joined, src: r.src}}
}

// emit writes c as standing for r's bytes [i, j).
func (d *derived) emit(c byte, i, j int) {
	lo, hi := d.r.source(i, j)
	d.b = append(d.b, c)
	d.out.lo = append(d.out.lo, int32(lo))
	d.out.hi = append(d.out.hi, int32(hi))
}

func (d *derived) emitRune(c rune, i, j int) {
	var buf [4]byte
	for _, b := range buf[:utf8.EncodeRune(buf[:], c)] {
		d.emit(b, i, j)
	}
}

func (d *derived) done() *reading {
	d.out.text = string(d.b)
	return d.out
}

// htmlEntities: the named entities a page's text decodes that can stand for a value's own bytes.
var htmlEntities = map[string]rune{
	"quot": '"', "amp": '&', "lt": '<', "gt": '>', "apos": '\'', "nbsp": ' ', "equals": '=', "colon": ':',
	"sol": '/', "bsol": '\\', "num": '#', "percnt": '%', "plus": '+', "comma": ',', "period": '.', "semi": ';',
	"lpar": '(', "rpar": ')', "lsqb": '[', "rsqb": ']', "lcub": '{', "rcub": '}', "excl": '!', "quest": '?',
	"ast": '*', "dollar": '$', "commat": '@', "lowbar": '_', "hyphen": '-', "grave": '`', "Hat": '^',
	"vert": '|', "tilde": '~', "Tab": '\t', "NewLine": '\n',
}

// htmlDecode reads `&name;`, `&#NN;` and `&#xHH;` as the character each stands for.
func (r *reading) htmlDecode() *reading {
	s := r.text
	d := r.derive(readDecoded)
	for i := 0; i < len(s); i++ {
		if s[i] == '&' {
			if c, n := htmlEntityAt(s, i); n > 0 {
				d.emitRune(c, i, i+n)
				i += n - 1
				continue
			}
		}
		d.emit(s[i], i, i+1)
	}
	return d.done()
}

// htmlEntityAt: the character an entity at i stands for and its length, 0 when there is none.
func htmlEntityAt(s string, i int) (rune, int) {
	j := i + 1
	if j < len(s) && s[j] == '#' {
		j++
		base := 10
		if j < len(s) && (s[j] == 'x' || s[j] == 'X') {
			base = 16
			j++
		}
		v, k := 0, j
		for k < len(s) && k-j < 7 {
			h, ok := unhex(s[k])
			if !ok || int(h) >= base {
				break
			}
			v = v*base + int(h)
			k++
		}
		if k == j || k >= len(s) || s[k] != ';' || v == 0 || v > utf8.MaxRune || (v >= 0xD800 && v < 0xE000) {
			return 0, 0
		}
		return rune(v), k + 1 - i
	}
	k := j
	for k < len(s) && k-j < 10 && isAlnumASCII(s[k]) {
		k++
	}
	if k < len(s) && s[k] == ';' {
		if c, ok := htmlEntities[s[j:k]]; ok {
			return c, k + 1 - i
		}
	}
	return 0, 0
}

// foldWidth reads fullwidth forms (U+FF01..U+FF5E) as their ASCII characters and the ideographic space as a space.
func (r *reading) foldWidth() *reading {
	s := r.text
	d := r.derive(readDecoded)
	for i := 0; i < len(s); {
		c, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case c >= 0xFF01 && c <= 0xFF5E:
			d.emit(byte(c-0xFEE0), i, i+n)
		case c == 0x3000:
			d.emit(' ', i, i+n)
		default:
			for k := i; k < i+n; k++ {
				d.emit(s[k], k, k+1)
			}
		}
		i += n
	}
	return d.done()
}

// looksLikeDiff: a line opens a hunk (`@@ -`). A `--- ` line alone is as often a Markdown rule.
func looksLikeDiff(s string) bool {
	return strings.HasPrefix(s, "@@ -") || strings.Contains(s, "\n@@ -")
}

// joinConts reads a line continuation (`\` then a line break) as nothing, as a shell joins the two lines; into a
// diff row, the row's marker goes with it.
func (r *reading) joinConts() *reading {
	s := r.text
	d := r.derive(readDecoded)
	diff := looksLikeDiff(s)
	for i := 0; i < len(s); i++ {
		if n := contAt(s, i); n > 0 {
			if k := i + n; k < len(s) && (s[k] == '+' || s[k] == '-') {
				// Into a diff's `+` or `-` row: a row of blanks then content joins without its marker. In a diff,
				// another is the other side's row, and a shell on this side never reads it.
				if k+1 < len(s) && (s[k+1] == ' ' || s[k+1] == '\t') {
					i += n
					continue
				}
				// Or a row of the other side right after this one (`-x \` then `+y`), headers or not.
				if cur := s[lineStart(s, i)]; diff || ((cur == '+' || cur == '-') && cur != s[k]) {
					d.emit(s[i], i, i+1)
					continue
				}
			}
			i += n - 1
			continue
		}
		d.emit(s[i], i, i+1)
	}
	return d.done()
}

// hasJSONEscape: `\n` `\r` `\t`, `\uXXXX`, `\xNN` or an octal escape somewhere in s.
func hasJSONEscape(s string) bool {
	for i := strings.IndexByte(s, '\\'); i >= 0 && i+1 < len(s); i = nextByte(s, '\\', i+2) {
		switch c := s[i+1]; {
		case c == 'n' || c == 'r' || c == 't' || (c >= '0' && c <= '7'):
			return true
		case c == 'u':
			if _, n := unicodeEscape(s, i); n > 0 {
				return true
			}
		case c == 'x':
			if i+3 < len(s) {
				if _, ok := unhex(s[i+2]); ok {
					if _, ok := unhex(s[i+3]); ok {
						return true
					}
				}
			}
		}
	}
	return false
}
