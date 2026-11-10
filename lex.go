package scrub

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// The lexer: where a value ends, decided in one place for every detector. Each function
// takes a reading's text and a start offset and returns an end offset (exclusive).

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// isWordAt: Python's `\w` at s[i] (a letter, digit or `_` in any script).
func isWordAt(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	if c < utf8.RuneSelf {
		return isAlnumASCII(c) || c == '_'
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

// wordBefore: Python's `\w` for the character ending just before i.
func wordBefore(s string, i int) bool {
	if i <= 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	if r < utf8.RuneSelf {
		return isAlnumASCII(byte(r)) || r == '_'
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || unicode.IsNumber(r) || unicode.Is(unicode.Mn, r)
}

func isNameChar(c byte) bool { return isAlnumASCII(c) || c == '_' || c == '-' }

// contAt: a line continuation (`\` then a line break) at i, and its length.
func contAt(s string, i int) int {
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

func lineEnd(s string, i int) int {
	if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(s)
}

func lineStart(s string, i int) int {
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

// sqEnd: a single-quoted part opening at i; no escapes. Closed it may span lines;
// unclosed it runs to the line end.
func sqEnd(s string, i int) int {
	if k := strings.IndexByte(s[i+1:], '\''); k >= 0 {
		return i + 1 + k + 1
	}
	return lineEnd(s, i+1)
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
			if contAt(s, j) > 0 {
				break
			}
			j++
			continue
		}
		if isSpaceByte(c) || c == '"' || c == '\'' {
			break
		}
		j++
	}
	return j
}

// valueEnd: a shell word starting at i: quoted and bare parts glued, continuations
// before any part. Returns i when there is no word.
func valueEnd(s string, i int) int {
	end := i
	j := i
	for {
		k := j
		for {
			n := contAt(s, k)
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
			e = sqEnd(s, k)
		default:
			e = bareEnd(s, k)
		}
		if e <= k {
			return end
		}
		end, j = e, e
	}
}

// valueEndFlow: an object literal's compact value (`{apiKey:"x"}`): quoted parts and
// characters other than space `,` `;` `}` `]`.
func valueEndFlow(s string, i int) int {
	j := i
	for j < len(s) {
		c := s[j]
		switch {
		case c == '"':
			j = dqEndLine(s, j)
		case c == '\'':
			j = sqEndEsc(s, j)
		case isSpaceByte(c) || c == ',' || c == ';' || c == '}' || c == ']':
			return j
		default:
			j++
		}
	}
	return j
}

// dqEndLine: `"(?:ESC|[^"\\\n])*"?`: to the closing quote or the line end.
func dqEndLine(s string, i int) int {
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

// sqEndEsc: `'(?:ESC|[^'\\\n])*'?`, a dict's single-quoted string with escapes.
func sqEndEsc(s string, i int) int {
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

// skipBlanks: spaces and tabs from i.
func skipBlanks(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// skipBlanksConts: spaces, tabs and continuations from i.
func skipBlanksConts(s string, i int) int {
	for i < len(s) {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		if n := contAt(s, i); n > 0 {
			i += n
			continue
		}
		break
	}
	return i
}

// skipSpaceConts: any whitespace (line breaks too) and continuations from i.
func skipSpaceConts(s string, i int) int {
	for i < len(s) {
		if isSpaceByte(s[i]) {
			i++
			continue
		}
		if n := contAt(s, i); n > 0 {
			i += n
			continue
		}
		break
	}
	return i
}

// nameRunBefore: the run of name characters `[A-Za-z0-9_-]` ending at i; its start.
func nameRunBefore(s string, i int) int {
	j := i
	for j > 0 && isNameChar(s[j-1]) {
		j--
	}
	return j
}

func nameRunAfter(s string, i int) int {
	j := i
	for j < len(s) && isNameChar(s[j]) {
		j++
	}
	return j
}

// trimDashes: a flag's dashes before a name.
func trimDashes(name string) string { return strings.TrimLeft(name, "-") }

// objectEnd: the object whose body begins at start ends just past its matching `}`, or at
// the end of the text if it never closes. Strings are skipped; a `"` or `'` ends with its
// line, a backtick string only at its closing backtick.
func objectEnd(s string, start int) int {
	depth := 1
	i := start
	for i < len(s) {
		c := s[i]
		if c == '"' || c == '\'' || c == '`' {
			i++
			for i < len(s) && s[i] != c && (c == '`' || s[i] != '\n') {
				if s[i] == '\\' {
					i += 2
				} else {
					i++
				}
			}
			if i < len(s) && s[i] == c {
				i++
			}
			continue
		}
		i++
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(s)
}

// isPlaceholderAt: a placeholder this package writes starts at i; its length.
func placeholderAt(s string, i int) int {
	for _, p := range placeholderWords {
		if strings.HasPrefix(s[i:], p) {
			return len(p)
		}
	}
	return 0
}

var placeholderWords = []string{"<redacted-jwt>", "<redacted>", "<long-token>", "[email]", "[phone]", "[owner]",
	"[teammate]", "[person]", "[vendor]", "…[cut]"}

// onlyPlaceholders: a value that is entirely placeholders, quotes, spaces, line breaks (each
// with a diff row's marker after it) and an auth scheme word is already hidden.
func onlyPlaceholders(v string) bool {
	v = strings.Trim(v, " \t\"'`\\")
	if v == "" {
		return false
	}
	found := false
	i := 0
	for i < len(v) {
		if n := placeholderAt(v, i); n > 0 {
			i += n
			found = true
			continue
		}
		c := v[i]
		if c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '\\' {
			i++
			continue
		}
		// A value read across rows of a diff: a line break and the next row's marker hold nothing.
		if c == '\n' || c == '\r' {
			i++
			if i < len(v) && v[i-1] == '\n' && (v[i] == '+' || v[i] == '-') {
				i++
			}
			continue
		}
		// An auth scheme word kept before a placeholder.
		j := i
		for j < len(v) && isAlnumASCII(v[j]) {
			j++
		}
		if j > i && authSchemes[strings.ToLower(v[i:j])] {
			i = j
			continue
		}
		return false
	}
	return found
}

// placeholderValue: Python's audit reading of a value as already hidden (scrub._PLACEHOLDER_VALUE
// after backstop_hit's trimming): quotes, backticks and backslashes trimmed from its ends, then
// placeholders (each perhaps after an auth scheme word) separated by blanks, and nothing else. A
// quote between two placeholders is part of the value.
func placeholderValue(v string) bool {
	v = strings.Trim(v, "\"'`\\")
	v = strings.Trim(v, " \t")
	if v == "" {
		return false
	}
	i := 0
	for {
		// an optional scheme word and blanks
		j := i
		for j < len(v) && isAlnumASCII(v[j]) {
			j++
		}
		if j > i && authSchemes[strings.ToLower(v[i:j])] {
			k := skipBlanks(v, j)
			if k > j {
				i = k
			}
		}
		n := placeholderAt(v, i)
		if n == 0 || strings.HasPrefix(v[i:], "…[cut]") {
			return false
		}
		i += n
		if i == len(v) {
			return true
		}
		k := skipBlanks(v, i)
		if k == i || k == len(v) {
			return false
		}
		i = k
	}
}

var authSchemes = setOf("bearer", "basic", "token", "digest", "negotiate", "ntlm", "ssws")

// asciiLower lowercases A-Z only, so every offset into it is an offset into s (Unicode case
// folding changes byte lengths, and a search in the folded text would aim at the wrong bytes).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
