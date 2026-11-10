package lex

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// The lexer: where a value ends, decided in one place for every detector. Each function
// takes a reading's text and a start offset and returns an end offset (exclusive).

func IsSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// IsWordAt: Python's `\w` at s[i] (a letter, digit or `_` in any script).
func IsWordAt(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	if c < utf8.RuneSelf {
		return IsAlnumASCII(c) || c == '_'
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	if r == utf8.RuneError {
		// A byte inside a multi-byte rune: judge the rune it belongs to.
		j := i
		for j > 0 && s[j]&0xC0 == 0x80 {
			j--
		}
		r, _ = utf8.DecodeRuneInString(s[j:])
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || unicode.Is(unicode.Mn, r) || unicode.IsNumber(r)
}

// WordBefore: Python's `\w` for the character ending just before i.
func WordBefore(s string, i int) bool {
	if i <= 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	if r < utf8.RuneSelf {
		return IsAlnumASCII(byte(r)) || r == '_'
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || unicode.IsNumber(r) || unicode.Is(unicode.Mn, r)
}

func IsNameChar(c byte) bool { return IsAlnumASCII(c) || c == '_' || c == '-' }

// ContAt: a line continuation (`\` then a line break) at i, and its length.
func ContAt(s string, i int) int {
	if i+1 < len(s) && s[i] == '\\' {
		if s[i+1] == '\n' {
			return 2
		}
		if s[i+1] == '\r' && i+2 < len(s) && s[i+2] == '\n' {
			return 3
		}
	}
	return 0
}

func LineEnd(s string, i int) int {
	if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(s)
}

func LineStart(s string, i int) int {
	return strings.LastIndexByte(s[:i], '\n') + 1
}

// dqEnd: a double-quoted part opening at i. Closed, it may span lines (escapes honoured);
// with no closing quote it runs to its line's end.
func dqEnd(s string, i int) int {
	j := i + 1
	for j < len(s) {
		c := s[j]
		if c == '\\' {
			if j+1 >= len(s) {
				break
			}
			j += 2
			if s[j-1] == '\r' && j < len(s) && s[j] == '\n' {
				j++
			}
			continue
		}
		if c == '"' {
			return j + 1
		}
		j++
	}
	// Unclosed: to the line end, an escaped line break continuing it.
	j = i + 1
	for j < len(s) {
		c := s[j]
		if c == '\\' {
			if j+1 >= len(s) {
				return j
			}
			j += 2
			if s[j-1] == '\r' && j < len(s) && s[j] == '\n' {
				j++
			}
			continue
		}
		if c == '\n' {
			return j
		}
		j++
	}
	return len(s)
}

// SqEnd: a single-quoted part opening at i; no escapes. Closed it may span lines;
// unclosed it runs to the line end.
func SqEnd(s string, i int) int {
	if k := strings.IndexByte(s[i+1:], '\''); k >= 0 {
		return i + 1 + k + 1
	}
	return LineEnd(s, i+1)
}

// bareEnd: an unquoted part at i, or i if there is none.
func bareEnd(s string, i int) int {
	j := i
	for j < len(s) {
		c := s[j]
		if c == '\\' {
			if j+1 < len(s) && (s[j+1] == ' ' || s[j+1] == '\t') {
				j += 2
				continue
			}
			if ContAt(s, j) > 0 {
				break
			}
			j++
			continue
		}
		if IsSpaceByte(c) || c == '"' || c == '\'' {
			break
		}
		j++
	}
	return j
}

// ValueEnd: a shell word starting at i: quoted and bare parts glued, continuations
// before any part. Returns i when there is no word.
func ValueEnd(s string, i int) int {
	end := i
	j := i
	for {
		k := j
		for {
			n := ContAt(s, k)
			if n == 0 {
				break
			}
			k += n
		}
		if k >= len(s) {
			return end
		}
		var e int
		switch s[k] {
		case '"':
			e = dqEnd(s, k)
		case '\'':
			e = SqEnd(s, k)
		default:
			e = bareEnd(s, k)
		}
		if e <= k {
			return end
		}
		end, j = e, e
	}
}

// ValueEndFlow: an object literal's compact value (`{apiKey:"x"}`): quoted parts and
// characters other than space `,` `;` `}` `]`.
func ValueEndFlow(s string, i int) int {
	j := i
	for j < len(s) {
		c := s[j]
		switch {
		case c == '"':
			j = DqEndLine(s, j)
		case c == '\'':
			j = SqEndEsc(s, j)
		case IsSpaceByte(c) || c == ',' || c == ';' || c == '}' || c == ']':
			return j
		default:
			j++
		}
	}
	return j
}

// DqEndLine: `"(?:ESC|[^"\\\n])*"?`: to the closing quote or the line end.
func DqEndLine(s string, i int) int {
	j := i + 1
	for j < len(s) {
		c := s[j]
		if c == '\\' {
			if j+1 >= len(s) {
				return j
			}
			j += 2
			if s[j-1] == '\r' && j < len(s) && s[j] == '\n' {
				j++
			}
			continue
		}
		if c == '"' {
			return j + 1
		}
		if c == '\n' {
			return j
		}
		j++
	}
	return j
}

// SqEndEsc: `'(?:ESC|[^'\\\n])*'?`, a dict's single-quoted string with escapes.
func SqEndEsc(s string, i int) int {
	j := i + 1
	for j < len(s) {
		c := s[j]
		if c == '\\' {
			if j+1 >= len(s) {
				return j
			}
			j += 2
			if s[j-1] == '\r' && j < len(s) && s[j] == '\n' {
				j++
			}
			continue
		}
		if c == '\'' {
			return j + 1
		}
		if c == '\n' {
			return j
		}
		j++
	}
	return j
}

// SkipBlanks: spaces and tabs from i.
func SkipBlanks(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// SkipBlanksConts: spaces, tabs and continuations from i.
func SkipBlanksConts(s string, i int) int {
	for i < len(s) {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		if n := ContAt(s, i); n > 0 {
			i += n
			continue
		}
		break
	}
	return i
}

// SkipSpaceConts: any whitespace (line breaks too) and continuations from i.
func SkipSpaceConts(s string, i int) int {
	for i < len(s) {
		if IsSpaceByte(s[i]) {
			i++
			continue
		}
		if n := ContAt(s, i); n > 0 {
			i += n
			continue
		}
		break
	}
	return i
}

func NextByte(s string, b byte, from int) int {
	if from >= len(s) {
		return -1
	}
	if k := strings.IndexByte(s[from:], b); k >= 0 {
		return from + k
	}
	return -1
}

// CrudeValue: the audit's own value extent at i: a quoted value to its closing quote on its
// line (or the line end), else a word to a space, a quote or `,` `;` `}` `]`.
func CrudeValue(s string, i int) (int, int) {
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
	for j < len(s) && !IsSpaceByte(s[j]) && s[j] != '"' && s[j] != '\'' {
		j++
	}
	return i, j
}
