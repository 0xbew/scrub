package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// headTypeWords: the words a type annotation after a credential's colon opens with (`token: str`).
var headTypeWords = []string{"str", "bytes", "int", "float", "bool", "None", "Any", "Optional", "Union", "SecretStr",
	"string", "number", "boolean", "undefined"}

// memberTypeWords: the words a union may also join (`str | null`, `string | unknown`).
var memberTypeWords = []string{"null", "nil", "void", "never", "unknown", "object", "list", "dict", "tuple", "set",
	"bigint", "symbol"}

// Bounds on a type's arguments (`Optional[Dict[str, Any]]`): the characters of one level, and of the level inside it.
const (
	maxTypeArgs      = 80
	maxInnerTypeArgs = 40
)

// IsTypeWord reports whether a type annotation stands at i (`token: str`, `token: str | None`, `Optional[str]`,
// `string!`), not a value that opens with a type word. Only type syntax may follow the word: type arguments (after
// `Optional`, `Union` or a union member), one `!` or `?`, `[]`, unions of named types, then a blank not before a
// literal, a delimiter, a default, a closing quote or the line's end. So `str.x9Kq`, `str "x9Kq"`, `str|int|x9Kq`,
// `str|"x9Kq"` and `Optional[x9Kq]` are values. A type word called (`str("x")`) is a value too.
func IsTypeWord(s string, i int) bool {
	n := typeWordEnd(s, i, headTypeWords)
	if n < 0 {
		return false
	}
	if w := s[i:n]; strings.EqualFold(w, "Optional") || strings.EqualFold(w, "Union") {
		n = typeArgsEnd(s, n)
	}
	n = unionEnd(s, typeSuffixEnd(s, n))
	return !danglingUnion(s, n) && typeEndAt(s, n)
}

// typeWordEnd: just past one of words standing whole at i, any case, and not called; -1 otherwise.
func typeWordEnd(s string, i int, words []string) int {
	for _, w := range words {
		n := i + len(w)
		if n <= len(s) && strings.EqualFold(s[i:n], w) && !lex.IsWordAt(s, n) && !calledAt(s, n) {
			return n
		}
	}
	return -1
}

// calledAt: a `(` at n, or blanks then a `(` with a quote later on its line (`str ("x")`, not `str (see docs)`).
func calledAt(s string, n int) bool {
	k := lex.SkipBlanks(s, n)
	if k >= len(s) || s[k] != '(' {
		return false
	}
	return k == n || strings.ContainsAny(s[k:lex.LineEnd(s, k)], "\"'`")
}

// typeSuffixEnd: past one `!` or `?`, then any `[]`, each with its own `!` or `?`.
func typeSuffixEnd(s string, n int) int {
	return arraySuffixEnd(s, bangEnd(s, n))
}

// bangEnd: past one `!` or `?` at n.
func bangEnd(s string, n int) int {
	if n < len(s) && (s[n] == '!' || s[n] == '?') {
		return n + 1
	}
	return n
}

// arraySuffixEnd: past any `[]` at n, each with its own `!` or `?`.
func arraySuffixEnd(s string, n int) int {
	for n+1 < len(s) && s[n] == '[' && s[n+1] == ']' {
		n = bangEnd(s, n+2)
	}
	return n
}

// typeArgsEnd: past type arguments at n (`[str, None]`, `<string>`, `["Token"]`, one level nested), or n when none
// stand there. A digit or other punctuation is no type's (`Optional[x9Kq]`).
func typeArgsEnd(s string, n int) int {
	if n >= len(s) || s[n] != '[' && s[n] != '<' {
		return n
	}
	open := s[n]
	closer, chars := byte(']'), "_., \t|\"'"
	if open == '<' {
		closer, chars = '>', "_., \t|?[]"
	}
	k := n + 1
	for k < len(s) && k-n <= maxTypeArgs && s[k] != closer {
		switch {
		case lex.IsUpperASCII(s[k]) || lex.IsLowerASCII(s[k]) || strings.IndexByte(chars, s[k]) >= 0:
			k++
		case s[k] == open:
			k = innerTypeArgsEnd(s, k, closer, chars)
			if k < 0 {
				return n
			}
		default:
			return n
		}
	}
	if k == n+1 || k >= len(s) || s[k] != closer {
		return n
	}
	return k + 1
}

// innerTypeArgsEnd: past the nested type arguments opening at k, or -1.
func innerTypeArgsEnd(s string, k int, closer byte, chars string) int {
	j := k + 1
	for j < len(s) && j-k <= maxInnerTypeArgs && (lex.IsUpperASCII(s[j]) || lex.IsLowerASCII(s[j]) ||
		strings.IndexByte(chars, s[j]) >= 0) && s[j] != closer {
		j++
	}
	if j >= len(s) || s[j] != closer {
		return -1
	}
	return j + 1
}

// unionEnd: past every `| member` or `& member` after n, a member being a type word or a capitalized name
// (`str | None`, `string|null`, `str | Literal["a"]`), each with its own arguments and suffixes.
func unionEnd(s string, n int) int {
	for {
		k := lex.SkipBlanks(s, n)
		ops := k
		for ops < len(s) && (s[ops] == '|' || s[ops] == '&') {
			ops++
		}
		if ops == k {
			return n
		}
		m := unionMemberEnd(s, lex.SkipBlanks(s, ops))
		if m < 0 {
			return n
		}
		n = m
	}
}

// unionMemberEnd: past the union member at i, or -1.
func unionMemberEnd(s string, i int) int {
	n := typeWordEnd(s, i, headTypeWords)
	if n < 0 {
		n = typeWordEnd(s, i, memberTypeWords)
	}
	if n < 0 {
		n = capitalizedNameEnd(s, i)
	}
	if n < 0 {
		return -1
	}
	return arraySuffixEnd(s, typeArgsEnd(s, bangEnd(s, n)))
}

// capitalizedNameEnd: past a type's name at i, lower-case owners then a capital and letters (`Token`, `models.User`),
// not called; -1 otherwise. A letter run with a digit or a lower-case start is a value (`hunter2`).
func capitalizedNameEnd(s string, i int) int {
	k := i
	for {
		j := k
		for j < len(s) && (lex.IsLowerASCII(s[j]) || s[j] == '_') {
			j++
		}
		if j == k || j >= len(s) || s[j] != '.' {
			break
		}
		k = j + 1
	}
	if k >= len(s) || !lex.IsUpperASCII(s[k]) {
		return -1
	}
	n := k + 1
	for n < len(s) && (lex.IsUpperASCII(s[n]) || lex.IsLowerASCII(s[n]) || s[n] == '_') {
		n++
	}
	if lex.IsWordAt(s, n) || calledAt(s, n) {
		return -1
	}
	return n
}

// danglingUnion: a `|` or `&` after n that joins something no member reads (`str|int|x9Kq`, `str|"x"`); a union
// operator ending the line joins nothing.
func danglingUnion(s string, n int) bool {
	k := lex.SkipBlanks(s, n)
	ops := k
	for ops < len(s) && (s[ops] == '|' || s[ops] == '&') {
		ops++
	}
	if ops == k {
		return false
	}
	k = lex.SkipBlanks(s, ops)
	return k < len(s) && s[k] != '\n' && s[k] != '\r'
}

// typeEndAt: what may follow a type at n: the line's or text's end, a blank not before a literal, a delimiter or a
// default, a run of `.` or `:` not before a word (`str.` ending a sentence), or a closing quote.
func typeEndAt(s string, n int) bool {
	if n >= len(s) {
		return true
	}
	c := s[n]
	switch {
	case c == '\n' || c == '\r':
		return true
	case lex.IsSpaceByte(c):
		k := lex.SkipBlanks(s, n)
		return k >= len(s) || strings.IndexByte("\"'`", s[k]) < 0
	case strings.IndexByte(",;)]}>=|&", c) >= 0:
		return true
	case c == '.' || c == ':':
		k := n
		for k < len(s) && (s[k] == '.' || s[k] == ':') {
			k++
		}
		return !lex.IsWordAt(s, k)
	case c == '"' || c == '\'' || c == '`':
		return !lex.IsWordAt(s, n+1)
	}
	return false
}
