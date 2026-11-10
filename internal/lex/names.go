package lex

import (
	"strings"
)

// NameRunBefore: the run of name characters `[A-Za-z0-9_-]` ending at i; its start.
func NameRunBefore(s string, i int) int {
	j := i
	for j > 0 && IsNameChar(s[j-1]) {
		j--
	}
	return j
}

func NameRunAfter(s string, i int) int {
	j := i
	for j < len(s) && IsNameChar(s[j]) {
		j++
	}
	return j
}

// TrimDashes: a flag's dashes before a name.
func TrimDashes(name string) string { return strings.TrimLeft(name, "-") }

// ObjectEnd: the object whose body begins at start ends just past its matching `}`, or at
// the end of the text if it never closes. Strings are skipped; a `"` or `'` ends with its
// line, a backtick string only at its closing backtick.
func ObjectEnd(s string, start int) int {
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
