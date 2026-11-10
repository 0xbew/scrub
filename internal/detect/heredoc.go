package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// HeredocValues: each heredoc that opens a credential's value after its name and `=` or `:` (`DB_PASSWORD=<<EOF`,
// `token: <<EOF`, mid-line or not), its body's span: the scrubber hides it and the audit refuses it live, so the two
// read the same shape. One opener a line is read, so a long line of openers stays linear.
func HeredocValues(s string, emit func(lo, hi int)) {
	lineDone := -1
	for p := strings.IndexAny(s, "=:"); p >= 0; {
		if p >= lineDone {
			if v := lex.SkipBlanks(s, p+1); strings.HasPrefix(s[v:], "<<") && !strings.HasPrefix(s[v:], "<<<") {
				e := p
				for e > 0 && (s[e-1] == ' ' || s[e-1] == '\t') {
					e--
				}
				if q := lex.NameRunBefore(s, e); q < e && vocab.IsCredentialName(lex.TrimDashes(s[q:e])) {
					lineDone = lex.LineEnd(s, v)
					if lo, hi, ok := heredocBodyAt(s, v); ok {
						emit(lo, hi)
					}
				}
			}
		}
		k := strings.IndexAny(s[p+1:], "=:")
		if k < 0 {
			return
		}
		p += 1 + k
	}
}

// heredocBodyAt: the body of a heredoc whose opener (`<<EOF`, `<<-'END'`) is at i: from the next line to the line
// that is its word alone (a diff row's marker aside), or to the end of the text when none is, as a cut command
// leaves it; never past heredocMaxLines lines.
func heredocBodyAt(s string, i int) (lo, hi int, ok bool) {
	j := i + 2
	if j < len(s) && (s[j] == '-' || s[j] == '~') {
		j++
	}
	var quote byte
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		quote = s[j]
		j++
	}
	w := j
	for j < len(s) && lex.IsWordAt(s, j) {
		j++
	}
	if j == w {
		return 0, 0, false
	}
	word := s[w:j]
	if quote != 0 && (j >= len(s) || s[j] != quote) {
		return 0, 0, false
	}
	le := lex.LineEnd(s, j)
	// An escaped line break after the opener is the escaped heredoc (JSON), read as its own reading.
	if strings.Contains(s[j:le], `\n`) || le >= len(s) {
		return 0, 0, false
	}
	lo = le + 1
	k := lo
	for n := 0; n < heredocMaxLines && k < len(s); n++ {
		e := lex.LineEnd(s, k)
		line := strings.TrimSpace(strings.TrimRight(s[k:e], "\r"))
		if line == word || len(line) > 1 && strings.IndexByte("+- ", s[k]) >= 0 && strings.TrimSpace(s[k+1:e]) == word {
			if k > lo {
				// The last body line's break (and its carriage return) stays with the terminator.
				hi = k - 1
				if hi > lo && s[hi-1] == '\r' {
					hi--
				}
				return lo, hi, true
			}
			return lo, lo, true
		}
		if e >= len(s) {
			return lo, len(s), true
		}
		k = e + 1
	}
	return lo, k, true
}

// heredocMaxLines: a heredoc body is read this many lines at most.
const heredocMaxLines = 2000

// HeredocAt: a real heredoc opener at i (`<<EOF` then a line break), its body's span.
func HeredocAt(s string, i int) (bodyLo, bodyHi int, ok bool) {
	if !strings.HasPrefix(s[i:], "<<") {
		return 0, 0, false
	}
	j := i + 2
	if j < len(s) && (s[j] == '-' || s[j] == '~') {
		j++
	}
	var quote byte
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		quote = s[j]
		j++
	}
	w := j
	for j < len(s) && lex.IsWordAt(s, j) {
		j++
	}
	if j == w {
		return 0, 0, false
	}
	word := s[w:j]
	if quote != 0 {
		if j >= len(s) || s[j] != quote {
			return 0, 0, false
		}
		j++
	}
	le := lex.LineEnd(s, j)
	rest := s[j:le]
	// An opener followed by an escaped line break is not one (JSON): the escaped heredoc.
	if strings.Contains(rest, `\n`) || le-j > 2000 || le >= len(s) {
		return 0, 0, false
	}
	body := le + 1
	k := body
	for n := 0; n < 200 && k < len(s); n++ {
		e := lex.LineEnd(s, k)
		line := strings.TrimRight(s[k:e], "\r")
		if strings.TrimSpace(line) == word {
			break
		}
		if e >= len(s) {
			break // a body line must end with its line break
		}
		k = e + 1
	}
	if k > body && s[k-1] == '\n' {
		k-- // the last body line's break stays with the terminator
	}
	return body, k, true
}

// escapedHeredocEnd: a heredoc written with escaped line breaks (`<<EOF\nx\nEOF`): one
// word to the next real space.
func escapedHeredocEnd(s string, i int) int {
	if !strings.HasPrefix(s[i:], "<<") {
		return i
	}
	le := lex.LineEnd(s, i)
	k := strings.Index(s[i:le], `\n`)
	if k < 0 {
		return i
	}
	j := i + k
	for j < le && !lex.IsSpaceByte(s[j]) && s[j] != '"' {
		if s[j] == '\\' && j+1 < le {
			j += 2
			continue
		}
		j++
	}
	return j
}

// heredocOpenerEnd: just past a heredoc's opener (`<<-"EOF"`) at i.
func heredocOpenerEnd(s string, i int) int {
	j := i + 2
	if j < len(s) && (s[j] == '-' || s[j] == '~') {
		j++
	}
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		j++
	}
	for j < len(s) && lex.IsWordAt(s, j) {
		j++
	}
	if j < len(s) && (s[j] == '"' || s[j] == '\'') {
		j++
	}
	return j
}
