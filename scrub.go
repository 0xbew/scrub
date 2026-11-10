// Package scrub is the one scrubber, and the pre-send audit every sender runs before text
// leaves the machine. Standard library only. See DESIGN.md.
package scrub

import "github.com/0xbew/scrub/internal/engine"

// Version: bump when a rule changes what is removed or what the audit refuses.
const Version = 1

// RedactMargin: the rules run on a little more than is sent, so a secret or a name
// straddling the cut is whole when they see it; the margin is never sent.
const RedactMargin = 512

// Cut is what replaces text past the limit.
const Cut = "…[cut]"

// The pipeline keeps its own copies of the two constants above; a duplicate map key fails the
// build if they ever differ.
var _ = map[bool]int{false: 0, RedactMargin == engine.RedactMargin && Cut == engine.Cut: 1}

// Scrub returns at most limit runes of text with secrets, addresses, phone numbers and the
// denylist's identities and vendors removed. With no denylist (nil, as a failed LoadDenylist
// leaves it) nothing is sent: the output is the cut marker alone. NoDenylist scrubs without one.
func Scrub(text string, d *Denylist, limit int) string {
	return engine.Scrub(text, d.list(), limit)
}

// Redact returns at most limit runes of text with secrets removed (no shapes, no denylist).
func Redact(text string, limit int) string { return engine.Redact(text, limit) }

// ScrubDiff is Scrub for a unified diff: each hunk side is read as its file holds it, and
// text it cannot read that way is read every way at once. Every row keeps its marker. A nil
// denylist sends nothing, as in Scrub.
func ScrubDiff(text string, d *Denylist, limit int) string {
	return engine.ScrubDiff(text, d.list(), limit)
}
