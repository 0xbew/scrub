package lex

import (
	"strings"
)

// isPlaceholderAt: a placeholder this package writes starts at i; its length.
func PlaceholderAt(s string, i int) int {
	for _, p := range PlaceholderWords {
		if strings.HasPrefix(s[i:], p) {
			return len(p)
		}
	}
	return 0
}

var PlaceholderWords = []string{"<redacted-jwt>", "<redacted>", "<long-token>", "[email]", "[phone]", "[owner]",
	"[teammate]", "[person]", "[vendor]", "…[cut]"}

// OnlyPlaceholders: a value that is entirely placeholders, quotes, spaces, line breaks (each
// with a diff row's marker after it) and an auth scheme word is already hidden.
func OnlyPlaceholders(v string) bool {
	v = strings.Trim(v, " \t\"'`\\")
	if v == "" {
		return false
	}
	found := false
	i := 0
	for i < len(v) {
		end, placeholder := hiddenPartEnd(v, i)
		if end < 0 {
			return false
		}
		if placeholder {
			found = true
		}
		i = end
	}
	return found
}

// hiddenPartEnd: the end of the part of v at i that holds nothing (a placeholder, a quote,
// backslash or blank, a line break with the next diff row's marker, or an auth scheme word),
// whether that part is a placeholder, and -1 when the part is anything else.
func hiddenPartEnd(v string, i int) (end int, placeholder bool) {
	if n := PlaceholderAt(v, i); n > 0 {
		return i + n, true
	}
	c := v[i]
	if c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '\\' {
		return i + 1, false
	}
	// A value read across rows of a diff: a line break and the next row's marker hold nothing.
	if c == '\n' || c == '\r' {
		i++
		if i < len(v) && v[i-1] == '\n' && (v[i] == '+' || v[i] == '-') {
			i++
		}
		return i, false
	}
	// An auth scheme word kept before a placeholder.
	j := i
	for j < len(v) && IsAlnumASCII(v[j]) {
		j++
	}
	if j > i && AuthSchemes[strings.ToLower(v[i:j])] {
		return j, false
	}
	return -1, false
}

// PlaceholderValue: Python's audit reading of a value as already hidden (scrub._PLACEHOLDER_VALUE
// after backstop_hit's trimming): quotes, backticks and backslashes trimmed from its ends, then
// placeholders (each perhaps after an auth scheme word) separated by blanks, and nothing else. A
// quote between two placeholders is part of the value.
func PlaceholderValue(v string) bool {
	v = strings.Trim(v, "\"'`\\")
	v = strings.Trim(v, " \t")
	if v == "" {
		return false
	}
	i := 0
	for {
		// an optional scheme word and blanks
		j := i
		for j < len(v) && IsAlnumASCII(v[j]) {
			j++
		}
		if j > i && AuthSchemes[strings.ToLower(v[i:j])] {
			k := SkipBlanks(v, j)
			if k > j {
				i = k
			}
		}
		n := PlaceholderAt(v, i)
		if n == 0 || strings.HasPrefix(v[i:], "…[cut]") {
			return false
		}
		i += n
		if i == len(v) {
			return true
		}
		k := SkipBlanks(v, i)
		if k == i || k == len(v) {
			return false
		}
		i = k
	}
}

var AuthSchemes = SetOf("bearer", "basic", "token", "digest", "negotiate", "ntlm", "ssws")

// AsciiLower lowercases A-Z only, so every offset into it is an offset into s (Unicode case
// folding changes byte lengths, and a search in the folded text would aim at the wrong bytes).
func AsciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// Placeholders, by what was hidden.
const (
	PhRedacted = "<redacted>"
	PhLong     = "<long-token>"
	PhJWT      = "<redacted-jwt>"
)
