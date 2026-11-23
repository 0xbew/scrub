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
			i = objectStringEnd(s, i, c)
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

// objectStringEnd: where the string the quote c at i opens ends: just past its closing quote; for an unclosed `"` or
// `'` string, at its line break; or at the text's end (past it by one when the last byte is a backslash, which skips
// the byte after it).
func objectStringEnd(s string, i int, c byte) int {
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
	return i
}

// maxSchemeTag bounds a scheme tag's name (`PBKDF2-SHA512`, `SHA512-CRYPT`, `PLAIN.BASE64`).
const maxSchemeTag = 32

// SchemeTagEnd returns the index just past a password scheme tag at i (`{SSHA}`, `{CRYPT}`, `{ARGON2}`,
// `{PBKDF2-SHA256}`) glued to the hash or password it labels, or -1. The tag is part of that value: the value does not
// stop at its `}`. A template's `{pw}` alone, before a quote, a closing bracket, a placeholder or the punctuation
// that ends a sentence is no tag.
func SchemeTagEnd(s string, i int) int {
	if i+1 >= len(s) || s[i] != '{' || !IsUpperASCII(s[i+1]) && !IsLowerASCII(s[i+1]) {
		return -1
	}
	j := i + 2
	for j < len(s) && j-i <= maxSchemeTag && (IsNameChar(s[j]) || s[j] == '.') {
		j++
	}
	if j >= len(s) || s[j] != '}' || !schemeTagGlued(s, j+1) {
		return -1
	}
	return j + 1
}

// schemeTagGlued: the byte at k starts a value glued to a tag's `}`. A password may open with any byte but a blank, a
// quote, a backslash or `,;)]}{<`; a run of `.!?:` opens one only with such a byte after it, else it ends a sentence.
func schemeTagGlued(s string, k int) bool {
	for k < len(s) && strings.IndexByte(".!?:", s[k]) >= 0 {
		k++
	}
	return k < len(s) && !IsSpaceByte(s[k]) && strings.IndexByte("\"'`\\,;)]}{<", s[k]) < 0
}

// LDIFBase64Colon reports whether the colon at p is the first of LDIF's `name:: value`, whose value is base64
// (`userPassword:: e1NT…`).
func LDIFBase64Colon(s string, p int) bool {
	return p+2 < len(s) && s[p] == ':' && s[p+1] == ':' && (s[p+2] == ' ' || s[p+2] == '\t')
}
