package reading

import (
	"unicode/utf8"
)

// A reading is a decoded view of a source text. Every byte of the reading knows the source
// span it came from, so a value found in a reading hides its source bytes, decoding and all.
type Reading struct {
	Text string
	Lo   []int32 // lo[i], hi[i]: the source span byte i of text came from
	Hi   []int32
	Kind readingKind
	Pct  bool // percent-decoded somewhere along the way, `+` read as a space
	// Pctd: percent-decoded somewhere along the way, `+` kept or not (pct is the stricter case).
	Pctd bool
	// Joined: an escaped `\n` `\r` `\t` was read as its letter, so the words either side of it
	// run together: shapes and long runs are not read here (the json reading has them apart).
	Joined bool
	Src    string // the source text the offsets point into
}

type readingKind uint8

const (
	ReadRaw readingKind = iota
	readUnescaped
	readPercent
	readDecoded // HTML entities, fullwidth folded, continuations joined
)

// maxEscapeLevels: how many levels of backslash escaping the readings undo.
const maxEscapeLevels = 8

func Raw(s string) *Reading {
	r := &Reading{Text: s, Lo: make([]int32, len(s)), Hi: make([]int32, len(s)), Kind: ReadRaw, Src: s}
	for i := range s {
		r.Lo[i], r.Hi[i] = int32(i), int32(i+1)
	}
	// range over a string steps by rune; fill the continuation bytes too.
	for i := 0; i < len(s); i++ {
		r.Lo[i], r.Hi[i] = int32(i), int32(i+1)
	}
	return r
}

// sameForm: the bytes at i and j were written the same way in the source (`"` and `"`, `%22`
// and `%22`, `\"` and `\"`). A value's closing quote is one written as its opening quote.
func (r *Reading) sameForm(i, j int) bool {
	if r == nil || r.Src == "" || i < 0 || j < 0 || i >= len(r.Lo) || j >= len(r.Lo) {
		return true
	}
	return r.Src[r.Lo[i]:r.Hi[i]] == r.Src[r.Lo[j]:r.Hi[j]]
}

// quoteFormEnd: a quoted value opening at i whose scan (end) stopped on a quote written
// another way (a raw `"` inside a `%22...%22` value) reads on, past each such quote, to one
// written as the opener, or to where next stops.
func (r *Reading) quoteFormEnd(s string, i, end int, next func(s string, i int) int) int {
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
func (r *Reading) contBreak(i int) bool {
	if r == nil || r.Src == "" || i >= len(r.Lo) {
		return false
	}
	lo, hi := int(r.Lo[i]), int(r.Hi[i])
	return hi-lo >= 2 && r.Src[lo] == '\\'
}

// QuotedEnd: a quoted value opening at i, as next scans it, read on past a quote written
// another way than the opener and past a continued line break.
func (r *Reading) QuotedEnd(s string, i int, next func(s string, i int) int) int {
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

// Source maps a reading span [a, b) to the source span it covers.
func (r *Reading) Source(a, b int) (int, int) {
	if a >= b {
		return 0, 0
	}
	lo, hi := int(r.Lo[a]), int(r.Hi[b-1])
	for i := a; i < b; i++ {
		if int(r.Lo[i]) < lo {
			lo = int(r.Lo[i])
		}
		if int(r.Hi[i]) > hi {
			hi = int(r.Hi[i])
		}
	}
	return lo, hi
}

// unescape removes one level of backslash escaping: `\x` becomes `x`, and `x` maps to the
// backslash and itself. A trailing lone backslash stays. With json, the level is read as a
// JSON string's: `\n` `\r` `\t` are line breaks and tabs and `\u00XX` is its character, so a
// line-start rule sees the line a serialized text starts. Without it, `\n` reads as `n`, and
// the reading is marked joined: words either side of it run together.
func (r *Reading) unescape(json bool) *Reading {
	s := r.Text
	out := &Reading{Kind: readUnescaped, Pct: r.Pct, Pctd: r.Pctd, Src: r.Src, Joined: r.Joined}
	b := make([]byte, 0, len(s))
	emit := func(c byte, lo, hi int32) {
		b = append(b, c)
		out.Lo = append(out.Lo, lo)
		out.Hi = append(out.Hi, hi)
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
					emit(c, r.Lo[i], r.Hi[i+1])
					i++
					continue
				}
				out.Joined = true
			case 'u':
				if json {
					if c, n := unicodeEscape(s, i); n > 0 {
						var buf [4]byte
						for _, b := range buf[:utf8.EncodeRune(buf[:], c)] {
							emit(b, r.Lo[i], r.Hi[i+n-1])
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
						emit(h<<4|l, r.Lo[i], r.Hi[i+3])
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
						emit(byte(v), r.Lo[i], r.Hi[i+n])
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
				emit(s[m], r.Lo[i], r.Hi[m])
			}
			i = k - 1
			continue
		}
		emit(s[i], r.Lo[i], r.Hi[i])
	}
	out.Text = string(b)
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
