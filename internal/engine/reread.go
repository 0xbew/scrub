package engine

import (
	"strings"

	"github.com/0xbew/scrub/internal/audit"
	"github.com/0xbew/scrub/internal/auditnet"
	"github.com/0xbew/scrub/internal/gate"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/span"
)

// maxRounds: how many times the rendered text is read again. What is rendered must scrub to
// itself, so a value that a placeholder joined to its neighbour (`{a: <redacted> b: x}`) is
// read again as the receiver will read it, and what that reading hides goes too.
const maxRounds = 8

// reread: what one more reading of the rendered text hides, in rendered offsets: the
// detectors (redetect), a value partly sent (fixup), and what the audit still reads as sent.
func reread(out string, keepLines bool, redetect func(string) *span.Set) *span.Set {
	more := &span.Set{}
	if redetect != nil {
		more = redetect(out)
	}
	if gate.Off(gate.RereadAudit) {
		return more
	}
	fixup(out, func(lo, hi int) { more.Add(lo, hi, span.KindSecret) })
	// What the audit's safety net reads as a token's rest glued to a long run goes too.
	auditnet.NetRemnants(out, func(lo, hi int) { more.Add(lo, hi, span.KindSecret) })
	for _, x := range audit.LocateLive(out).Spans {
		lo, hi := x.Lo, x.Hi
		if keepLines {
			// A diff row keeps its marker and its line: the value is clipped to its row.
			if lo == lex.LineStart(out, lo) {
				lo++
			}
			if e := lex.LineEnd(out, lo); e < hi {
				hi = e
			}
		}
		more.Add(lo, hi, span.KindSecret)
	}
	return more
}

// renderFixed renders, then reads the rendered text again (with redetect) and hides what
// that reading finds, mapped back to the source, until the rendering holds still. Still
// changing when the rounds run out, what a next round would hide could be a value, so it never
// goes out: the lines before the first one that round changes are kept when they hold still,
// and otherwise nothing is.
func renderFixed(s string, spans *span.Set, keepLines bool, redetect func(string) *span.Set) string {
	out, src := render(s, spans, keepLines)
	for round := 0; round <= maxRounds; round++ {
		more := reread(out, keepLines, redetect)
		if len(more.Spans) == 0 && !gate.Off(gate.Converge) {
			return out
		}
		addMappedBack(spans, more, src)
		next, nsrc := render(s, spans, keepLines)
		if next == out && gate.Off(gate.Converge) {
			next = out + " "
		}
		if next == out {
			return out
		}
		if round == maxRounds {
			return unsettledCut(out, next, keepLines, redetect)
		}
		out, src = next, nsrc
	}
	return out
}

// addMappedBack adds each span the rereading found, mapped from rendered offsets back to the source; an empty
// span or one past the rendering's source map is skipped.
func addMappedBack(spans, more *span.Set, src [][2]int) {
	for _, sp := range more.Spans {
		if sp.Lo >= sp.Hi || sp.Hi > len(src) {
			continue
		}
		spans.Add(src[sp.Lo][0], src[sp.Hi-1][1], sp.Kind)
	}
}

// unsettledCut: what goes out when the rendering still changes after the last round: the lines before the
// first byte that round changed, when they read clean again, then the cut marker; otherwise the marker alone.
func unsettledCut(out, next string, keepLines bool, redetect func(string) *span.Set) string {
	k := 0
	for k < len(out) && k < len(next) && out[k] == next[k] {
		k++
	}
	head := out[:strings.LastIndexByte(out[:k], '\n')+1]
	if head != "" && len(reread(head, keepLines, redetect).Spans) == 0 {
		return head + Cut
	}
	return Cut
}
