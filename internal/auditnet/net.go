package auditnet

import (
	"github.com/0xbew/scrub/internal/denylist"
	"github.com/0xbew/scrub/internal/reading"
)

// The audit's safety net (contract rule 9): its own checks for what the scrubber's detectors hide, so a
// detector that goes blind does not take the audit with it. Nothing here calls a detector or the scan's rules
// (tokenSpans, the long-run, address and phone readers, identityMatches); each check is its own and narrower
// than the detector it backs, so the net refuses only what the scrubber hides when it works. A hit is a
// refusal only: the scrubber's own re-read (locateLive) never sees the net, so it never changes an output.

// NetHits: the rules the net finds in the readings of the texts.
func NetHits(readings []*reading.Reading, d *denylist.List) map[string]bool {
	found := map[string]bool{}
	for _, r := range readings {
		s := r.Text
		if !found["secret:token-format"] && netToken(s) {
			found["secret:token-format"] = true
		}
		if !found["secret:token-format"] && netTokenRemnant(s) {
			found["secret:token-format"] = true
		}
		if !found["secret:jwt"] && netJWTRemnant(s) {
			found["secret:jwt"] = true
		}
		if !found["secret:header"] && netCookie(s) {
			found["secret:header"] = true
		}
		if !found["secret:colon-value"] && netNamedValue(s) {
			found["secret:colon-value"] = true
		}
		if r.Joined {
			continue // words either side of an escaped line break run together: no runs, shapes or options here
		}
		if !found["secret:flag-value"] && netProgramOption(s) {
			found["secret:flag-value"] = true
		}
		if !found["secret:long-run"] && netLongRun(s) {
			found["secret:long-run"] = true
		}
		if !found["email"] && netEmail(s) {
			found["email"] = true
		}
		if !r.Pctd && !found["phone"] && netPhone(s) {
			found["phone"] = true
		}
		if d != nil {
			for _, id := range d.Identities {
				if !found[id.Rule] && netIdentity(id, s) {
					found[id.Rule] = true
				}
			}
		}
	}
	return found
}
