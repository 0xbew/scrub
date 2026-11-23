package reading

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// pieces builds a reading from pieces of a source text, each mapped to its own bytes.
type pieces struct {
	src string
	b   strings.Builder
	lo  []int32
	hi  []int32
}

func (p *pieces) add(from, to int) {
	for i := from; i < to; i++ {
		p.b.WriteByte(p.src[i])
		p.lo = append(p.lo, int32(i))
		p.hi = append(p.hi, int32(i+1))
	}
}

func (p *pieces) reading() *Reading {
	return &Reading{Text: p.b.String(), Lo: p.lo, Hi: p.hi, Src: p.src}
}

// PhoneReadings: each side of a whole diff hunk (as many rows as its header counts) on its
// own, its rows without their marker, so the `+` that marks an added row is never a country
// code's; a hunk that stops short, and every other line, read as written. Each is a reading
// mapped onto text, so the scrubber hides what the audit finds there.
func PhoneReadings(text string) []*Reading {
	h := &hunkSides{text: text}
	for _, ln := range lex.DiffLines(text) {
		h.line(ln)
	}
	h.releaseHeld()
	return append(h.out, h.join(h.written))
}

type textLine struct{ start, end int }

type heldLine struct {
	line   textLine
	marker string
}

// hunkSides splits a text into the readings PhoneReadings returns, one line at a time: the lines read as
// written so far, and the rows of the hunk being read, held until it is whole.
type hunkSides struct {
	text       string
	out        []*Reading
	written    []textLine
	hold       []heldLine
	oldN, newN int
}

func (h *hunkSides) join(ls []textLine) *Reading {
	p := &pieces{src: h.text}
	for _, l := range ls {
		p.add(l.start, l.end)
	}
	return p.reading()
}

func (h *hunkSides) line(ln lex.DiffLine) {
	text := h.text
	l := textLine{ln.Start, ln.End}
	marker := ""
	if ln.End > ln.Start {
		marker = text[ln.Start : ln.Start+1]
	}
	if h.oldN > 0 || h.newN > 0 {
		if h.hunkRow(l, marker) {
			return
		}
	}
	if o, n, _, ok := lex.HunkHeader(text[ln.Start:ln.Body]); ok {
		h.oldN, h.newN = o, n
	}
	h.written = append(h.written, l)
}

// hunkRow holds the line l when it is a row of the hunk being read (or a `\` note) and reports so; else the
// hunk stopped short, and its held rows read as written.
func (h *hunkSides) hunkRow(l textLine, marker string) bool {
	row := (marker == "+" && h.newN > 0) || (marker == "-" && h.oldN > 0) ||
		((marker == " " || marker == "\n" || marker == "\r") && h.oldN > 0 && h.newN > 0)
	if row || marker == "\\" {
		if row {
			if marker != "+" {
				h.oldN--
			}
			if marker != "-" {
				h.newN--
			}
		}
		h.hold = append(h.hold, heldLine{l, marker})
		if h.oldN == 0 && h.newN == 0 {
			h.wholeHunk()
		}
		return true
	}
	h.releaseHeld()
	h.hold, h.oldN, h.newN = nil, 0, 0
	return false
}

// wholeHunk: the lines read as written before the hunk, then each side of it, then its `\` notes.
func (h *hunkSides) wholeHunk() {
	h.out = append(h.out, h.join(h.written))
	for _, side := range []string{"+", "-"} {
		h.out = append(h.out, h.side(side))
	}
	for _, x := range h.hold {
		if x.marker == "\\" {
			h.out = append(h.out, h.join([]textLine{x.line}))
		}
	}
	h.written, h.hold = nil, nil
}

// side: the held rows of one side of the hunk and its context rows, a marked row without its marker.
func (h *hunkSides) side(side string) *Reading {
	p := &pieces{src: h.text}
	for _, x := range h.hold {
		if x.marker == side || x.marker == " " || x.marker == "\n" || x.marker == "\r" {
			if x.marker == "+" || x.marker == "-" || x.marker == " " {
				p.add(x.line.start+1, x.line.end)
			} else {
				p.add(x.line.start, x.line.end)
			}
		}
	}
	return p.reading()
}

// releaseHeld: the held rows read as written.
func (h *hunkSides) releaseHeld() {
	for _, x := range h.hold {
		h.written = append(h.written, x.line)
	}
}
