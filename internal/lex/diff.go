package lex

import (
	"strconv"
	"strings"
)

// A unified diff is read one side at a time, as its file holds it: the new side is the
// context and added rows in order, the old side the context and removed rows, markers
// stripped. Each side is a reading whose bytes map back to the diff, so a secret continued
// onto the next row is hidden there too, and every row keeps its marker and line ending.

type DiffLine struct {
	Start, End int // the line, its ending included
	Body       int // end of the body (before the line ending)
}

func DiffLines(s string) []DiffLine {
	var out []DiffLine
	i := 0
	for i < len(s) {
		e := LineEnd(s, i)
		end := e
		if e < len(s) {
			end = e + 1
		}
		body := e
		if body > i && s[body-1] == '\r' && e < len(s) {
			body--
		}
		out = append(out, DiffLine{i, end, body})
		i = end
	}
	return out
}

// HunkHeader: `@@ -a[,b] +c[,d] @@` at a line's start: the old and new counts and its end.
func HunkHeader(s string) (oldN, newN, end int, ok bool) {
	if !strings.HasPrefix(s, "@@ -") {
		return 0, 0, 0, false
	}
	i := 4
	num := func() (int, int, bool) {
		j := i
		for j < len(s) && IsDigitASCII(s[j]) && j-i < 18 {
			j++
		}
		if j == i || (j < len(s) && IsDigitASCII(s[j])) {
			return 0, i, false
		}
		n, err := strconv.Atoi(s[i:j])
		return n, j, err == nil
	}
	if _, j, ok := num(); ok {
		i = j
	} else {
		return 0, 0, 0, false
	}
	oldN = 1
	if i < len(s) && s[i] == ',' {
		i++
		n, j, ok := num()
		if !ok {
			return 0, 0, 0, false
		}
		oldN, i = n, j
	}
	if !strings.HasPrefix(s[i:], " +") {
		return 0, 0, 0, false
	}
	i += 2
	if _, j, ok := num(); ok {
		i = j
	} else {
		return 0, 0, 0, false
	}
	newN = 1
	if i < len(s) && s[i] == ',' {
		i++
		n, j, ok := num()
		if !ok {
			return 0, 0, 0, false
		}
		newN, i = n, j
	}
	if !strings.HasPrefix(s[i:], " @@") {
		return 0, 0, 0, false
	}
	return oldN, newN, i + 3, true
}
