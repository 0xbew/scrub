package engine

import (
	"unicode/utf8"

	"github.com/0xbew/scrub/internal/audit"

	"github.com/0xbew/scrub/internal/denylist"
	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
)

// RedactMargin: the rules run on a little more than is sent, so a secret or a name
// straddling the cut is whole when they see it; the margin is never sent.
const RedactMargin = 512

// Cut is what replaces text past the limit.
const Cut = "…[cut]"

type mode uint8

const (
	modeScrub  mode = iota // secrets, shapes, denylist
	modeRedact             // secrets only
)

// detectAll: the hidden spans of a base reading (source offsets), from every reading of it
// and every detector. Shapes, JWTs, long runs and the denylist read every reading too,
// except one whose escaped `\n` was read as a letter (its json twin reads it apart).
func detectAll(base *reading.Reading, d *denylist.List, m mode, out *span.Set) {
	for _, r := range reading.Of(base, true) {
		detect.Run(detect.Secrets, &detect.Scan{S: r.Text, R: r, Out: out})
		if r.Joined {
			continue
		}
		rc := &detect.Scan{S: r.Text, R: r, Out: out}
		detect.Run(detect.Runs, rc)
		if m == modeScrub {
			rc.Shapes()
			if d != nil {
				sp := &span.Set{}
				d.Apply(r.Text, sp)
				for _, x := range sp.Spans {
					rc.Hide(x.Lo, x.Hi, x.Kind)
				}
			}
		}
	}
}

func detectText(window string, d *denylist.List, m mode) *span.Set {
	out := &span.Set{}
	detectAll(reading.Raw(window), d, m, out)
	return out
}

// Scrub returns at most limit runes of text with secrets, addresses, phone numbers and the
// denylist's identities and vendors removed. With no denylist (nil, as a failed LoadDenylist
// leaves it) nothing is sent: the output is the cut marker alone. NoDenylist scrubs without one.
func Scrub(text string, d *denylist.List, limit int) string {
	limit = clampLimit(limit)
	return fit(scrub(text, d, limit), limit)
}

func scrub(text string, d *denylist.List, limit int) string {
	if d == nil {
		return Cut
	}
	return settled(text, func(t string) (string, bool) {
		window := firstRunes(t, limit+RedactMargin)
		out := renderFixed(window, detectText(window, d, modeScrub), false, func(t string) *span.Set { return detectText(t, d, modeScrub) })
		out = reshape(out)
		res := cut(out, limit, utf8.RuneCountInString(t))
		return res, res != out
	})
}

// Redact returns at most limit runes of text with secrets removed (no shapes, no denylist).
func Redact(text string, limit int) string {
	limit = clampLimit(limit)
	return fit(redact(text, limit), limit)
}

func redact(text string, limit int) string {
	return settled(text, func(t string) (string, bool) {
		window := firstRunes(t, limit+RedactMargin)
		out := renderFixed(window, detectText(window, denylist.None, modeRedact), false, func(t string) *span.Set { return detectText(t, denylist.None, modeRedact) })
		res := cut(out, limit, utf8.RuneCountInString(t))
		return res, res != out
	})
}

// maxLimit keeps limit+RedactMargin from overflowing an int, and keeps the text a cut output is
// re-audited on (up to limit runes) inside what the audit reads.
const maxLimit = audit.MaxBytes / utf8.UTFMax

// clampLimit: a negative limit sends nothing, and a huge one is the largest the margin allows.
func clampLimit(limit int) int {
	return min(max(limit, 0), maxLimit)
}

// fit: the cut marker is itself longer than a limit below its length, and the limit is a promise: send nothing.
func fit(out string, limit int) string {
	if out == Cut && limit < utf8.RuneCountInString(Cut) {
		return ""
	}
	return out
}

// settled: one scrub, and a cut output scrubbed once more. The cut takes away text the first reading paired with
// what it kept (a closing quote past the limit), so the kept text read alone can find more, and scrubbing the output
// again would change it. Once only: a second cut means the rounds did not settle, and that output stands.
func settled(text string, once func(string) (string, bool)) string {
	out, wasCut := once(text)
	if !wasCut || out == Cut {
		return out
	}
	again, _ := once(out)
	return again
}
