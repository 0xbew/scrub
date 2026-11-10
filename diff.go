package scrub

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// A unified diff is read one side at a time, as its file holds it: the new side is the
// context and added rows in order, the old side the context and removed rows, markers
// stripped. Each side is a reading whose bytes map back to the diff, so a secret continued
// onto the next row is hidden there too, and every row keeps its marker and line ending.

type diffLine struct {
	start, end int // the line, its ending included
	body       int // end of the body (before the line ending)
}

func diffLines(s string) []diffLine {
	var out []diffLine
	i := 0
	for i < len(s) {
		e := lineEnd(s, i)
		end := e
		if e < len(s) {
			end = e + 1
		}
		body := e
		if body > i && s[body-1] == '\r' && e < len(s) {
			body--
		}
		out = append(out, diffLine{i, end, body})
		i = end
	}
	return out
}

type hunk struct {
	header    diffLine
	headerEnd int // end of `@@ ... @@`
	rows      []int
}

type diffPart struct {
	text  []int // line indexes of text between hunks
	hunk  *hunk
	slash []int // `\ No newline` rows of the previous hunk
}

// hunkHeader: `@@ -a[,b] +c[,d] @@` at a line's start: the old and new counts and its end.
func hunkHeader(s string) (oldN, newN, end int, ok bool) {
	if !strings.HasPrefix(s, "@@ -") {
		return 0, 0, 0, false
	}
	i := 4
	num := func() (int, int, bool) {
		j := i
		for j < len(s) && isDigitASCII(s[j]) && j-i < 18 {
			j++
		}
		if j == i || (j < len(s) && isDigitASCII(s[j])) {
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

// parseDiff: text between hunks and the hunks; ok false when a line breaks the structure its
// hunk header promises. A hunk may stop short only where the text was cut.
func parseDiff(s string, lines []diffLine, wasCut bool) (parts []diffPart, ok bool) {
	var between []int
	var cur *hunk
	oldN, newN := 0, 0
	for li, ln := range lines {
		body := s[ln.start:ln.body]
		if oldN > 0 || newN > 0 {
			marker := ""
			if body != "" {
				marker = body[:1]
			}
			switch {
			case marker == "+" && newN > 0:
				newN--
			case marker == "-" && oldN > 0:
				oldN--
			case (marker == " " || marker == "") && oldN > 0 && newN > 0:
				oldN--
				newN--
			case marker == "\\":
			default:
				return nil, false
			}
			cur.rows = append(cur.rows, li)
			continue
		}
		if strings.HasPrefix(body, "\\") && cur != nil && len(between) == 0 {
			cur.rows = append(cur.rows, li)
			continue
		}
		if o, n, e, isHunk := hunkHeader(body); isHunk {
			if len(between) > 0 {
				parts = append(parts, diffPart{text: between})
				between = nil
			}
			oldN, newN = o, n
			cur = &hunk{header: ln, headerEnd: ln.start + e}
			parts = append(parts, diffPart{hunk: cur})
			continue
		}
		if body != "" && strings.IndexByte("+- ", body[0]) >= 0 && !strings.HasPrefix(body, "--- ") && !strings.HasPrefix(body, "+++ ") {
			return nil, false
		}
		between = append(between, li)
	}
	if (oldN > 0 || newN > 0) && !wasCut {
		return nil, false
	}
	if len(between) > 0 {
		parts = append(parts, diffPart{text: between})
	}
	return parts, true
}

// sideReading: the rows' contents after their markers, with their line endings, as one
// reading mapped onto the diff.
func sideReading(s string, lines []diffLine, rows []int, skip int) *reading {
	r := &reading{src: s}
	var b strings.Builder
	for _, li := range rows {
		ln := lines[li]
		from := ln.start + skip
		if from > ln.body {
			from = ln.body
		}
		for i := from; i < ln.end; i++ {
			b.WriteByte(s[i])
			r.lo = append(r.lo, int32(i))
			r.hi = append(r.hi, int32(i+1))
		}
	}
	r.text = b.String()
	return r
}

// chunkReading: lines as written, mapped onto the diff.
func chunkReading(s string, lines []diffLine, idx []int) *reading {
	return sideReading(s, lines, idx, 0)
}

// contReading: lines with the marker after a continuation dropped (`+a \` then `+b`), so a
// value continued past one marker reads whole.
func contReading(s string, lines []diffLine, idx []int) *reading {
	r := &reading{src: s}
	var b strings.Builder
	prevCont := false
	for _, li := range idx {
		ln := lines[li]
		from := ln.start
		if prevCont && from < ln.body && strings.IndexByte("+- ", s[from]) >= 0 {
			from++
		}
		for i := from; i < ln.end; i++ {
			b.WriteByte(s[i])
			r.lo = append(r.lo, int32(i))
			r.hi = append(r.hi, int32(i+1))
		}
		body := s[ln.start:ln.body]
		prevCont = strings.HasSuffix(body, "\\")
	}
	r.text = b.String()
	return r
}

func isRowBody(body string) bool { return body == "" || strings.IndexByte("+- ", body[0]) >= 0 }

// fallback: lines not read with confidence as hunk sides are read every way at once.
func fallbackSpans(s string, lines []diffLine, idx []int, d *Denylist, out *spanSet, protect []bool) {
	if len(idx) == 0 {
		return
	}
	detect(chunkReading(s, lines, idx), d, modeScrub, out)
	detect(contReading(s, lines, idx), d, modeScrub, out)
	// Runs of row-like lines, as a new and an old side.
	for i := 0; i < len(idx); {
		if !isRowBody(s[lines[idx[i]].start:lines[idx[i]].body]) {
			i++
			continue
		}
		j := i
		for j < len(idx) && isRowBody(s[lines[idx[j]].start:lines[idx[j]].body]) {
			j++
		}
		run := idx[i:j]
		sides(s, lines, run, d, out)
		for _, li := range run {
			if lines[li].body > lines[li].start {
				protect[lines[li].start] = true
			}
		}
		i = j
	}
}

// sides: the new and the old side of rows, each read whole.
func sides(s string, lines []diffLine, rows []int, d *Denylist, out *spanSet) {
	for _, keep := range []string{"+ ", "- "} {
		var side []int
		for _, li := range rows {
			body := s[lines[li].start:lines[li].body]
			if body == "" || strings.IndexByte(keep, body[0]) >= 0 {
				side = append(side, li)
			}
		}
		if len(side) > 0 {
			detect(sideReading(s, lines, side, 1), d, modeScrub, out)
		}
	}
}

// diffSpans: the hidden spans of a diff text, markers and line breaks never among them.
func diffSpans(window string, d *Denylist, wasCut bool) *spanSet {
	lines := diffLines(window)
	out := &spanSet{}
	protect := make([]bool, len(window))
	parts, ok := parseDiff(window, lines, wasCut)
	if !ok {
		all := make([]int, len(lines))
		for i := range lines {
			all[i] = i
		}
		fallbackSpans(window, lines, all, d, out, protect)
	} else {
		for _, p := range parts {
			if p.hunk == nil {
				fallbackSpans(window, lines, p.text, d, out, protect)
				continue
			}
			h := p.hunk
			// The ranges are digits; after them git repeats a line of the file.
			rest := &reading{text: window[h.headerEnd:h.header.body], src: window}
			for i := h.headerEnd; i < h.header.body; i++ {
				rest.lo = append(rest.lo, int32(i))
				rest.hi = append(rest.hi, int32(i+1))
			}
			detect(rest, d, modeScrub, out)
			var rows, slashes []int
			for _, li := range h.rows {
				if strings.HasPrefix(window[lines[li].start:lines[li].body], "\\") {
					slashes = append(slashes, li)
					continue
				}
				rows = append(rows, li)
				if lines[li].body > lines[li].start {
					protect[lines[li].start] = true
				}
			}
			sides(window, lines, rows, d, out)
			// Addresses as the rows are written too: a diff quoting a diff holds ` +@pytest.mark.x`, which the
			// receiver (Python's audit) reads as an address though its side starts the line with it.
			for _, li := range rows {
				ln := lines[li]
				if ln.body > ln.start+1 {
					emails(window[ln.start:ln.body], func(lo, hi int) {
						if lo == 0 {
							lo = 1 // never the row's marker
						}
						out.add(ln.start+lo, ln.start+hi, KindEmail)
					})
				}
			}
			for _, li := range slashes {
				detect(chunkReading(window, lines, []int{li}), d, modeScrub, out)
			}
		}
	}
	kept := &spanSet{}
	for _, sp := range out.spans {
		lo := sp.Lo
		for i := sp.Lo; i < sp.Hi; i++ {
			if protect[i] {
				if i > lo {
					kept.add(lo, i, sp.Kind)
				}
				lo = i + 1
			}
		}
		kept.add(lo, sp.Hi, sp.Kind)
	}
	return kept
}

// ScrubDiff is Scrub for a unified diff: each hunk side is read as its file holds it, and
// text it cannot read that way is read every way at once. Every row keeps its marker. A nil
// denylist sends nothing, as in Scrub.
func ScrubDiff(text string, d *Denylist, limit int) string {
	if d == nil {
		return Cut
	}
	return settled(text, func(text string) (string, bool) {
		length := utf8.RuneCountInString(text)
		window := firstRunes(text, limit+RedactMargin)
		wasCut := length > utf8.RuneCountInString(window)
		spans := diffSpans(window, d, wasCut)
		rendered := renderFixed(window, spans, true, func(t string) *spanSet { return diffSpans(t, d, wasCut) })
		rows := reshapeRows(rendered)
		res := cut(rows, limit, length)
		return res, res != rows
	})
}

// reshapeRows: addresses and phone numbers again on each rendered row, its marker aside.
func reshapeRows(out string) string {
	var b strings.Builder
	for _, ln := range diffLines(out) {
		line := out[ln.start:ln.end]
		if line != "" && strings.IndexByte("+- ", line[0]) >= 0 {
			b.WriteByte(line[0])
			b.WriteString(reshape(line[1:]))
			continue
		}
		b.WriteString(reshape(line))
	}
	return b.String()
}
