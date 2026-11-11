package engine

import (
	"strings"
	"unicode/utf8"

	"github.com/0xbew/scrub/internal/denylist"
	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
)

type hunk struct {
	header    lex.DiffLine
	headerEnd int // end of `@@ ... @@`
	rows      []int
}

type diffPart struct {
	text  []int // line indexes of text between hunks
	hunk  *hunk
	slash []int // `\ No newline` rows of the previous hunk
}

// parseDiff: text between hunks and the hunks; ok false when a line breaks the structure its
// hunk header promises. A hunk may stop short only where the text was cut.
func parseDiff(s string, lines []lex.DiffLine, wasCut bool) (parts []diffPart, ok bool) {
	var between []int
	var cur *hunk
	oldN, newN := 0, 0
	for li, ln := range lines {
		body := s[ln.Start:ln.Body]
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
		if o, n, e, isHunk := lex.HunkHeader(body); isHunk {
			if len(between) > 0 {
				parts = append(parts, diffPart{text: between})
				between = nil
			}
			oldN, newN = o, n
			cur = &hunk{header: ln, headerEnd: ln.Start + e}
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
func sideReading(s string, lines []lex.DiffLine, rows []int, skip int) *reading.Reading {
	r := &reading.Reading{Src: s}
	var b strings.Builder
	for _, li := range rows {
		ln := lines[li]
		from := ln.Start + skip
		if from > ln.Body {
			from = ln.Body
		}
		for i := from; i < ln.End; i++ {
			b.WriteByte(s[i])
			r.Lo = append(r.Lo, int32(i))
			r.Hi = append(r.Hi, int32(i+1))
		}
	}
	r.Text = b.String()
	return r
}

// chunkReading: lines as written, mapped onto the diff.
func chunkReading(s string, lines []lex.DiffLine, idx []int) *reading.Reading {
	return sideReading(s, lines, idx, 0)
}

// contReading: lines with the marker after a continuation dropped (`+a \` then `+b`), so a
// value continued past one marker reads whole.
func contReading(s string, lines []lex.DiffLine, idx []int) *reading.Reading {
	r := &reading.Reading{Src: s}
	var b strings.Builder
	prevCont := false
	for _, li := range idx {
		ln := lines[li]
		from := ln.Start
		if prevCont && from < ln.Body && strings.IndexByte("+- ", s[from]) >= 0 {
			from++
		}
		for i := from; i < ln.End; i++ {
			b.WriteByte(s[i])
			r.Lo = append(r.Lo, int32(i))
			r.Hi = append(r.Hi, int32(i+1))
		}
		body := s[ln.Start:ln.Body]
		prevCont = strings.HasSuffix(body, "\\")
	}
	r.Text = b.String()
	return r
}

func isRowBody(body string) bool { return body == "" || strings.IndexByte("+- ", body[0]) >= 0 }

// fallback: lines not read with confidence as hunk sides are read every way at once.
func fallbackSpans(s string, lines []lex.DiffLine, idx []int, d *denylist.List, out *span.Set, protect []bool) {
	if len(idx) == 0 {
		return
	}
	detectAll(chunkReading(s, lines, idx), d, modeScrub, out)
	detectAll(contReading(s, lines, idx), d, modeScrub, out)
	// Runs of row-like lines, as a new and an old side.
	for i := 0; i < len(idx); {
		if !isRowBody(s[lines[idx[i]].Start:lines[idx[i]].Body]) {
			i++
			continue
		}
		j := i
		for j < len(idx) && isRowBody(s[lines[idx[j]].Start:lines[idx[j]].Body]) {
			j++
		}
		run := idx[i:j]
		sides(s, lines, run, d, out)
		for _, li := range run {
			if lines[li].Body > lines[li].Start {
				protect[lines[li].Start] = true
			}
		}
		i = j
	}
}

// sides: the new and the old side of rows, each read whole.
func sides(s string, lines []lex.DiffLine, rows []int, d *denylist.List, out *span.Set) {
	for _, keep := range []string{"+ ", "- "} {
		var side []int
		for _, li := range rows {
			body := s[lines[li].Start:lines[li].Body]
			if body == "" || strings.IndexByte(keep, body[0]) >= 0 {
				side = append(side, li)
			}
		}
		if len(side) > 0 {
			detectAll(sideReading(s, lines, side, 1), d, modeScrub, out)
		}
	}
}

// diffSpans: the hidden spans of a diff text, markers and line breaks never among them.
func diffSpans(window string, d *denylist.List, wasCut bool) *span.Set {
	lines := lex.DiffLines(window)
	out := &span.Set{}
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
			rest := &reading.Reading{Text: window[h.headerEnd:h.header.Body], Src: window}
			for i := h.headerEnd; i < h.header.Body; i++ {
				rest.Lo = append(rest.Lo, int32(i))
				rest.Hi = append(rest.Hi, int32(i+1))
			}
			detectAll(rest, d, modeScrub, out)
			var rows, slashes []int
			for _, li := range h.rows {
				if strings.HasPrefix(window[lines[li].Start:lines[li].Body], "\\") {
					slashes = append(slashes, li)
					continue
				}
				rows = append(rows, li)
				if lines[li].Body > lines[li].Start {
					protect[lines[li].Start] = true
				}
			}
			sides(window, lines, rows, d, out)
			// Addresses as the rows are written too: a diff quoting a diff holds ` +@pytest.mark.x`, which the
			// receiver (Python's audit) reads as an address though its side starts the line with it.
			for _, li := range rows {
				ln := lines[li]
				if ln.Body > ln.Start+1 {
					detect.Emails(window[ln.Start:ln.Body], func(lo, hi int) {
						if lo == 0 {
							lo = 1 // never the row's marker
						}
						out.Add(ln.Start+lo, ln.Start+hi, span.KindEmail)
					})
				}
			}
			for _, li := range slashes {
				detectAll(chunkReading(window, lines, []int{li}), d, modeScrub, out)
			}
		}
	}
	kept := &span.Set{}
	for _, sp := range out.Spans {
		lo := sp.Lo
		for i := sp.Lo; i < sp.Hi; i++ {
			if protect[i] {
				if i > lo {
					kept.Add(lo, i, sp.Kind)
				}
				lo = i + 1
			}
		}
		kept.Add(lo, sp.Hi, sp.Kind)
	}
	return kept
}

// ScrubDiff is Scrub for a unified diff: each hunk side is read as its file holds it, and
// text it cannot read that way is read every way at once. Every row keeps its marker. A nil
// denylist sends nothing, as in Scrub.
func ScrubDiff(text string, d *denylist.List, limit int) string {
	limit = clampLimit(limit)
	return fit(scrubDiff(text, d, limit), limit)
}

func scrubDiff(text string, d *denylist.List, limit int) string {
	if d == nil {
		return Cut
	}
	return settled(text, func(text string) (string, bool) {
		length := utf8.RuneCountInString(text)
		window := firstRunes(text, limit+RedactMargin)
		wasCut := length > utf8.RuneCountInString(window)
		spans := diffSpans(window, d, wasCut)
		rendered := renderFixed(window, spans, true, func(t string) *span.Set { return diffSpans(t, d, wasCut) })
		rows := reshapeRows(rendered)
		res := cut(rows, limit, length)
		return res, res != rows
	})
}

// reshapeRows: addresses and phone numbers again on each rendered row, its marker aside.
func reshapeRows(out string) string {
	var b strings.Builder
	for _, ln := range lex.DiffLines(out) {
		line := out[ln.Start:ln.End]
		if line != "" && strings.IndexByte("+- ", line[0]) >= 0 {
			b.WriteByte(line[0])
			b.WriteString(reshape(line[1:]))
			continue
		}
		b.WriteString(reshape(line))
	}
	return b.String()
}
