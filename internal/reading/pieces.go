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
	var out []*Reading
	type line struct{ start, end int }
	var written []line
	type held struct {
		line   line
		marker string
	}
	var hold []held
	join := func(ls []line) *Reading {
		p := &pieces{src: text}
		for _, l := range ls {
			p.add(l.start, l.end)
		}
		return p.reading()
	}
	oldN, newN := 0, 0
	for _, ln := range lex.DiffLines(text) {
		l := line{ln.Start, ln.End}
		marker := ""
		if ln.End > ln.Start {
			marker = text[ln.Start : ln.Start+1]
		}
		if oldN > 0 || newN > 0 {
			row := (marker == "+" && newN > 0) || (marker == "-" && oldN > 0) ||
				((marker == " " || marker == "\n" || marker == "\r") && oldN > 0 && newN > 0)
			if row || marker == "\\" {
				if row {
					if marker != "+" {
						oldN--
					}
					if marker != "-" {
						newN--
					}
				}
				hold = append(hold, held{l, marker})
				if oldN == 0 && newN == 0 {
					out = append(out, join(written))
					for _, side := range []string{"+", "-"} {
						p := &pieces{src: text}
						for _, h := range hold {
							if h.marker == side || h.marker == " " || h.marker == "\n" || h.marker == "\r" {
								if h.marker == "+" || h.marker == "-" || h.marker == " " {
									p.add(h.line.start+1, h.line.end)
								} else {
									p.add(h.line.start, h.line.end)
								}
							}
						}
						out = append(out, p.reading())
					}
					for _, h := range hold {
						if h.marker == "\\" {
							out = append(out, join([]line{h.line}))
						}
					}
					written, hold = nil, nil
				}
				continue
			}
			for _, h := range hold {
				written = append(written, h.line)
			}
			hold, oldN, newN = nil, 0, 0
		}
		if o, n, _, ok := lex.HunkHeader(text[ln.Start:ln.Body]); ok {
			oldN, newN = o, n
		}
		written = append(written, l)
	}
	for _, h := range hold {
		written = append(written, h.line)
	}
	return append(out, join(written))
}
