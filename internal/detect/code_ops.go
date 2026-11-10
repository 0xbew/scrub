package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// Code: assignments in source (`password = "x"`, `token := x`, `:secret => x`,
// `api_key: str = x`, `var apiKey string = x`), an argument after a credential's quoted name
// (`getenv("API_KEY", "x")`), heredocs, YAML block scalars, SQL, Dockerfile ENV and setx.

const (
	maxStatementLines = 12
	maxLiteralChars   = 4000
)

// CodeOpAfter: a code assignment operator after a name ending at e. Returns where the
// value starts (after the operator and a continuation), or -1. goType allows a type after
// a bare word (`name string =`), which the audit allows only after `var`.
func CodeOpAfter(s string, e int, goType bool) int {
	k := e
	// The name may be quoted (a level down) and indexed: `os.environ["DB_PASSWORD"] = x`.
	for k < len(s) && s[k] == '\\' {
		k++
	}
	closedQuote := false
	if k < len(s) && (s[k] == '"' || s[k] == '\'') {
		k++
		closedQuote = true
	}
	if k < len(s) && s[k] == ']' {
		k++
		closedQuote = true
	}
	if !closedQuote {
		k = e
	}
	op := plainOp(s, k, closedQuote)
	if op < 0 {
		op = typedOp(s, k, goType)
	}
	if op < 0 && closedQuote {
		op = plainOp(s, e, false)
		if op < 0 {
			op = typedOp(s, e, goType)
		}
	}
	if op < 0 {
		return -1
	}
	// OP_TAIL: blanks, and a continuation then blanks and diff markers.
	j := lex.SkipBlanks(s, op)
	if n := lex.ContAt(s, j); n > 0 {
		j += n
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '+' || s[j] == '-') {
			j++
		}
	}
	return j
}

func notCompare(s string, i int) bool {
	return i >= len(s) || (s[i] != '=' && s[i] != '~' && s[i] != '>')
}

// plainOp: `:=` `=>` `?=` `+=` `||=` `&&=` `??=` (after blanks), ` =` (a blank before), `= `
// (a blank after), and `=` straight after a closing quote or bracket.
func plainOp(s string, k int, afterQuote bool) int {
	j := lex.SkipBlanks(s, k)
	for _, op := range []string{":=", "=>", "||=", "&&=", "??=", "?=", "+="} {
		if strings.HasPrefix(s[j:], op) {
			if (op == "?=" || op == "+=") && !notCompareEq(s, j+2) {
				continue
			}
			return j + len(op)
		}
	}
	if j < len(s) && s[j] == '=' && notCompare(s, j+1) {
		if j > k {
			return j + 1 // `[ \t]+=`
		}
		if j+1 < len(s) && (s[j+1] == ' ' || s[j+1] == '\t') {
			return j + 1
		}
		if afterQuote {
			return j + 1
		}
	}
	return -1
}

func notCompareEq(s string, i int) bool { return i >= len(s) || s[i] != '=' }

// typedOp: an annotation `: Type =` or (goType) a type after a blank `name T =`.
func typedOp(s string, k int, goType bool) int {
	j := lex.SkipBlanks(s, k)
	if j < len(s) && s[j] == ':' {
		t := lex.SkipBlanks(s, j+1)
		if t < len(s) && (s[t] == '"' || s[t] == '\'') {
			t++
		}
		if e := typeNameEnd(s, t, false); e > t {
			if e < len(s) && (s[e] == '"' || s[e] == '\'') {
				e++
			}
			e = subscriptEnd(s, e)
			o := lex.SkipBlanks(s, e)
			if o < len(s) && s[o] == '=' && notCompare(s, o+1) {
				return o + 1
			}
		}
		return -1
	}
	if goType && j > k {
		if e := typeNameEnd(s, j, true); e > j {
			e = subscriptEnd(s, e)
			o := lex.SkipBlanks(s, e)
			if o < len(s) && s[o] == '=' && notCompare(s, o+1) {
				return o + 1
			}
		}
	}
	return -1
}

func typeNameEnd(s string, i int, star bool) int {
	if i >= len(s) || !(lex.IsLowerASCII(s[i]) || lex.IsUpperASCII(s[i]) || s[i] == '_') {
		return i
	}
	j := i + 1
	for j < len(s) && (lex.IsWordAt(s, j) || s[j] == '.' || (star && s[j] == '*')) {
		j++
	}
	return j
}

// subscriptEnd: a bounded `[...]` one level nested (`dict[str, list[int]]`).
func subscriptEnd(s string, i int) int {
	if i >= len(s) || s[i] != '[' {
		return i
	}
	depth := 0
	for j := i; j < len(s) && j-i < 200; j++ {
		switch s[j] {
		case '[':
			depth++
			if depth > 2 {
				return i
			}
		case ']':
			depth--
			if depth == 0 {
				return j + 1
			}
		case '\n':
			return i
		}
	}
	return i
}

// openers: `(` or `{` after the operator, each perhaps followed by a line break and an
// indented next line.
func OpenersEnd(s string, i int) int {
	j := i
	for j < len(s) && (s[j] == '(' || s[j] == '{') {
		j = lex.SkipBlanks(s, j+1)
		k := j
		if k < len(s) && s[k] == '\r' {
			k++
		}
		if k < len(s) && s[k] == '\n' {
			k++
			for k < len(s) && (s[k] == ' ' || s[k] == '\t' || s[k] == '+' || s[k] == '-') {
				k++
			}
			j = k
		}
	}
	return j
}
