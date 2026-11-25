package lex

import "strings"

// Opener is a literal's opening: where it starts (a prefix such as `r` or `f` included), where its opening ends, the
// backslashes before its quote and the quote.
type Opener struct {
	Start, Open    int
	Slashes, Quote string
}

// LiteralOpen returns the next literal opener in s[from:to]. A run of three quotes of one kind, backticks too, is
// one triple quote: a credential's value ends where its literals do, and the audit reads the same literals, so the two
// must pair a run of backticks alike.
func LiteralOpen(s string, from, to int) (Opener, bool) {
	for i := from; i < to; i++ {
		ch := s[i]
		if ch != '"' && ch != '\'' && ch != '`' {
			continue
		}
		q := string(ch)
		if i+2 < len(s) && s[i+1] == ch && s[i+2] == ch {
			q = strings.Repeat(q, 3)
		}
		b := i
		for b > from && s[b-1] == '\\' {
			b--
		}
		st := b
		for k := 0; k < 2 && st > from && strings.IndexByte("rRbBuUfFnNeE", s[st-1]) >= 0; k++ {
			st--
		}
		return Opener{Start: st, Open: i + len(q), Slashes: s[b:i], Quote: q}, true
	}
	return Opener{}, false
}

// LiteralEnd returns just past a literal's closing quote, and the closing, or the statement's end and "" when it does
// not close. A triple quote or a backtick may close lines later, up to maxLiteralChars on.
func LiteralEnd(s string, open int, slashes, quote string, end int) (int, string) {
	far := end
	if len(quote) == 3 || quote == "`" {
		far = min(open+maxLiteralChars, len(s))
	}
	if slashes != "" || len(quote) == 3 {
		closing := slashes + quote
		for at := open; at < far; {
			k := strings.Index(s[at:far], closing)
			if k < 0 {
				break
			}
			cl := at + k
			if slashes == "" || cl == 0 || s[cl-1] != '\\' {
				return cl + len(closing), closing
			}
			at = cl + 1
		}
		return end, ""
	}
	i := open
	for i < far {
		ch := s[i]
		switch {
		case ch == '\\':
			i += 2
		case string(ch) == quote:
			return i + 1, quote
		case ch == '\n' && quote != "`":
			return i, ""
		default:
			i++
		}
	}
	return min(i, end), ""
}
