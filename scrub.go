// Package scrub is the one scrubber, and the pre-send audit every sender runs before text
// leaves the machine. Standard library only. See DESIGN.md.
package scrub

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Version: bump when a rule changes what is removed or what the audit refuses.
const Version = 1

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

// detect: the hidden spans of a base reading (source offsets), from every reading of it
// and every detector. Shapes, JWTs, long runs and the denylist read every reading too,
// except one whose escaped `\n` was read as a letter (its json twin reads it apart).
func detect(base *reading, d *Denylist, m mode, out *spanSet) {
	for _, r := range readingsOf(base, true) {
		detectReading(r, out)
		if r.joined {
			continue
		}
		rc := &scan{s: r.text, r: r, out: out}
		rc.jwt()
		rc.longRuns()
		if m == modeScrub {
			rc.shapes()
			if d != nil {
				sp := &spanSet{}
				d.apply(r.text, sp)
				for _, x := range sp.spans {
					rc.hide(x.Lo, x.Hi, x.Kind)
				}
			}
		}
	}
}

func detectText(window string, d *Denylist, m mode) *spanSet {
	out := &spanSet{}
	detect(rawReading(window), d, m, out)
	return out
}

// detectReading runs the secret detectors over one reading.
func detectReading(r *reading, out *spanSet) {
	c := &scan{s: r.text, r: r, out: out}
	c.named()
	heredocValues(c.s, func(lo, hi int) {
		if lo < hi && !onlyPlaceholders(c.s[lo:hi]) {
			c.hide(lo, hi, KindSecret)
		}
	})
	c.colon()
	c.flags()
	c.programOptions()
	c.headers()
	c.bearer()
	c.userinfo()
	c.netrc()
	c.quotedAssignments()
	c.tokens()
	if !r.pct {
		c.code()
	}
}

// Placeholders, by what was hidden.
const (
	phRedacted = "<redacted>"
	phLong     = "<long-token>"
	phJWT      = "<redacted-jwt>"
)

func label(kinds uint16) string {
	secret := kinds & (1<<KindSecret | 1<<KindLong | 1<<KindJWT)
	switch {
	case secret == 1<<KindLong && kinds == secret:
		return phLong
	case secret == 1<<KindJWT && kinds == secret:
		return phJWT
	case secret != 0:
		return phRedacted
	case kinds&(1<<KindEmail) != 0:
		return "[email]"
	case kinds&(1<<KindPhone) != 0:
		return "[phone]"
	case kinds&(1<<KindOwner) != 0:
		return "[owner]"
	case kinds&(1<<KindTeammate) != 0:
		return "[teammate]"
	case kinds&(1<<KindPerson) != 0:
		return "[person]"
	case kinds&(1<<KindVendor) != 0:
		return "[vendor]"
	}
	return phRedacted
}

// render replaces each maximal run of hidden bytes with one placeholder. With keepLines, a
// line break is never hidden; otherwise one inside a hidden span goes with it, as one value.
// It also returns, for each output byte, the source span it stands for.
func render(s string, spans *spanSet, keepLines bool) (string, [][2]int) {
	mask := make([]uint16, len(s))
	for _, sp := range spans.spans {
		lo, hi := sp.Lo, sp.Hi
		if lo < 0 {
			lo = 0
		}
		if hi > len(s) {
			hi = len(s)
		}
		for i := lo; i < hi; i++ {
			mask[i] |= 1 << sp.Kind
		}
	}
	// Whole runes: a run never splits one.
	for i := 0; i < len(s); i++ {
		if mask[i] != 0 && s[i] >= utf8.RuneSelf {
			j := i
			for j > 0 && s[j]&0xC0 == 0x80 {
				j--
			}
			_, sz := utf8.DecodeRuneInString(s[j:])
			for k := j; k < j+sz && k < len(s); k++ {
				mask[k] |= mask[i]
			}
		}
	}
	// A bracket opened inside a hidden run is the value's: its closer right after goes too.
	for i := 0; i < len(s); {
		if mask[i] == 0 {
			i++
			continue
		}
		j := i
		var open []byte
		for j < len(s) && mask[j] != 0 {
			switch s[j] {
			case '(', '[', '{':
				open = append(open, s[j])
			case ')', ']', '}':
				if len(open) > 0 && open[len(open)-1] == opener(s[j]) {
					open = open[:len(open)-1]
				}
			}
			j++
		}
		for j < len(s) && len(open) > 0 && opener(s[j]) == open[len(open)-1] {
			mask[j] = mask[j-1]
			open = open[:len(open)-1]
			j++
		}
		i = j
	}
	// A lone quote between two hidden runs is a value's, paired wrongly: it goes with them.
	for i := 1; i+1 < len(s); i++ {
		if mask[i] == 0 && (s[i] == '"' || s[i] == '\'') && mask[i-1] != 0 && mask[i+1] != 0 {
			mask[i] = mask[i-1]
		}
	}
	isBreak := func(i int) bool { return s[i] == '\n' || s[i] == '\r' }
	var b strings.Builder
	var src [][2]int
	i := 0
	for i < len(s) {
		if mask[i] == 0 || (keepLines && isBreak(i)) {
			b.WriteByte(s[i])
			src = append(src, [2]int{i, i + 1})
			i++
			continue
		}
		j := i
		var kinds uint16
		for j < len(s) && mask[j] != 0 && !(keepLines && isBreak(j)) {
			kinds |= mask[j]
			j++
		}
		ph := label(kinds)
		b.WriteString(ph)
		for k := 0; k < len(ph); k++ {
			src = append(src, [2]int{i, j})
		}
		i = j
	}
	return b.String(), src
}

// opener: the bracket a closer closes, or 0.
func opener(c byte) byte {
	switch c {
	case ')':
		return '('
	case ']':
		return '['
	case '}':
		return '{'
	}
	return 0
}

// fixup: a value that holds a placeholder and anything else is a value partly sent: the
// whole value goes. Read in every reading of the rendered text; emit takes rendered offsets.
func fixup(out string, emit func(lo, hi int)) {
	for _, r := range readingsOf(rawReading(out), true) {
		t := r.text
		for p := strings.IndexByte(t, '='); p >= 0; p = nextByte(t, '=', p+1) {
			q := nameRunBefore(t, p)
			if q == p {
				continue
			}
			name := trimDashes(t[q:p])
			if name == "" || !(IsCredentialName(name) || hasKeyword(name)) {
				continue
			}
			lo, hi := auditWordAt(t, p+1)
			inQuotes := false
			// A quoted word that opens with the assignment holds its value to its closing quote.
			if q > 0 && (t[q-1] == '"' || t[q-1] == '\'') {
				inQuotes = true
				e := p + 1
				for e < len(t) && t[e] != t[q-1] && t[e] != '\n' {
					e++
				}
				if e > hi {
					hi = e
				}
			}
			v := t[lo:hi]
			if !strings.Contains(v, "<redacted") && !strings.Contains(v, "<long-token>") {
				continue
			}
			// A credential's value, as a receiver splits it from `NAME=` (a quoted string, or a run to a
			// space or quote), is the placeholder alone or it is a value partly sent: a closer or an
			// escape glued to it (`api_key=<redacted>)`) goes with it.
			bare := strings.Trim(t[lo:hi], "\"'")
			strict := !inQuotes && IsCredentialName(name) && bare != "" && bare != phRedacted
			if !strict && (onlyPlaceholders(v) || (!inQuotes && heldOnlyAt(t, lo, hi))) {
				continue
			}
			if len(v) > 1 && (v[0] == '"' || v[0] == '\'') {
				lo++
				if v[len(v)-1] == v[0] {
					hi--
				}
			}
			olo, ohi := r.source(lo, hi)
			if olo < ohi {
				emit(olo, ohi)
			}
		}
	}
}

// auditWordAt: the receiver's reading of a value after `=`: `"..."?`, `'...'?`, or a run
// without a space or quote.
func auditWordAt(s string, i int) (int, int) {
	if i >= len(s) {
		return i, i
	}
	switch s[i] {
	case '"':
		return i, dqEndLine(s, i)
	case '\'':
		le := lineEnd(s, i+1)
		if k := strings.IndexByte(s[i+1:le], '\''); k >= 0 {
			return i, i + k + 2
		}
		return i, le
	}
	j := i
	for j < len(s) && !isSpaceByte(s[j]) && s[j] != '"' && s[j] != '\'' {
		j++
	}
	return i, j
}

// maxRounds: how many times the rendered text is read again. What is rendered must scrub to
// itself, so a value that a placeholder joined to its neighbour (`{a: <redacted> b: x}`) is
// read again as the receiver will read it, and what that reading hides goes too.
const maxRounds = 8

// reread: what one more reading of the rendered text hides, in rendered offsets: the
// detectors (redetect), a value partly sent (fixup), and what the audit still reads as sent.
func reread(out string, keepLines bool, redetect func(string) *spanSet) *spanSet {
	more := &spanSet{}
	if redetect != nil {
		more = redetect(out)
	}
	if off("reread-audit") {
		return more
	}
	fixup(out, func(lo, hi int) { more.add(lo, hi, KindSecret) })
	// What the audit's safety net reads as a token's rest glued to a long run goes too.
	netRemnants(out, func(lo, hi int) { more.add(lo, hi, KindSecret) })
	for _, x := range locateLive(out).spans {
		lo, hi := x.Lo, x.Hi
		if keepLines {
			// A diff row keeps its marker and its line: the value is clipped to its row.
			if lo == lineStart(out, lo) {
				lo++
			}
			if e := lineEnd(out, lo); e < hi {
				hi = e
			}
		}
		more.add(lo, hi, KindSecret)
	}
	return more
}

// renderFixed renders, then reads the rendered text again (with redetect) and hides what
// that reading finds, mapped back to the source, until the rendering holds still. Still
// changing when the rounds run out, what a next round would hide could be a value, so it never
// goes out: the lines before the first one that round changes are kept when they hold still,
// and otherwise nothing is.
func renderFixed(s string, spans *spanSet, keepLines bool, redetect func(string) *spanSet) string {
	out, src := render(s, spans, keepLines)
	for round := 0; round <= maxRounds; round++ {
		more := reread(out, keepLines, redetect)
		if len(more.spans) == 0 && !off("converge") {
			return out
		}
		for _, sp := range more.spans {
			if sp.Lo >= sp.Hi || sp.Hi > len(src) {
				continue
			}
			spans.add(src[sp.Lo][0], src[sp.Hi-1][1], sp.Kind)
		}
		next, nsrc := render(s, spans, keepLines)
		if next == out && off("converge") {
			next = out + " "
		}
		if next == out {
			return out
		}
		if round == maxRounds {
			k := 0
			for k < len(out) && k < len(next) && out[k] == next[k] {
				k++
			}
			head := out[:strings.LastIndexByte(out[:k], '\n')+1]
			if head != "" && len(reread(head, keepLines, redetect).spans) == 0 {
				return head + Cut
			}
			return Cut
		}
		out, src = next, nsrc
	}
	return out
}

// firstRunes: the first n runes of s.
func firstRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for k := 0; k < n && i < len(s); k++ {
		_, sz := utf8.DecodeRuneInString(s[i:])
		i += sz
	}
	return s[:i]
}

// cut: scrubbed text of at most limit runes, from an original of length runes.
func cut(text string, limit, length int) string {
	if length > limit+RedactMargin {
		// The rules stopped at the window's edge, so what sat on it was never read whole.
		n := utf8.RuneCountInString(text) - RedactMargin
		if n < 0 {
			n = 0
		}
		text = firstRunes(text, n)
	}
	if length > limit || utf8.RuneCountInString(text) > limit {
		// The marker counts against the limit, so a cut output is itself within it and scrubs to itself.
		head := firstRunes(text, limit-utf8.RuneCountInString(" "+Cut))
		if !strings.Contains(head, " ") {
			return Cut
		}
		// Never end on part of a token: it could be the start of a secret or a name.
		k := strings.LastIndexFunc(head, unicode.IsSpace)
		kept := strings.TrimRightFunc(head[:k], unicode.IsSpace)
		// Nor on a name whose value the cut took: `password: …[cut]` reads as a value left.
		// A hidden value right after such a name reads as more of it with the marker (`TOKEN= <redacted> …[cut]`).
		for {
			w := strings.LastIndexFunc(kept, unicode.IsSpace)
			if w < 0 {
				break
			}
			last := kept[w+1:]
			if !awaitsValue(last) {
				rest := strings.TrimRightFunc(kept[:w], unicode.IsSpace)
				pw := strings.LastIndexFunc(rest, unicode.IsSpace)
				if !onlyPlaceholders(strings.Trim(last, "\"'`")) || !awaitsValue(rest[pw+1:]) {
					break
				}
			}
			kept = strings.TrimRightFunc(kept[:w], unicode.IsSpace)
		}
		// Nor where the audit reads the marker as a value left (a name in another form, `＝ …[cut]`, or a
		// closed value read on into the marker): words go from the end until it passes.
		// Only what the marker itself causes: a hit already in the kept text is not the cut's to answer.
		baseHit := secretHit(kept)
		baseMore := len(reread(kept, false, redetectSecrets).spans) > 0
		for (!baseHit && secretHit(kept+" "+Cut)) || (!baseMore && len(reread(kept+" "+Cut, false, redetectSecrets).spans) > 0) {
			w := strings.LastIndexFunc(kept, unicode.IsSpace)
			if w < 0 {
				return Cut
			}
			kept = strings.TrimRightFunc(kept[:w], unicode.IsSpace)
		}
		return kept + " " + Cut
	}
	return text
}

// redetectSecrets: the secret detectors over a text, as a cut output is read again.
func redetectSecrets(t string) *spanSet { return detectText(t, NoDenylist, modeRedact) }

// secretHit: the audit reads a secret's value in s (its secret rules; names and shapes are not the cut's).
func secretHit(s string) bool {
	for _, h := range Audit(s, NoDenylist) {
		if strings.HasPrefix(h, "secret:") {
			return true
		}
	}
	return false
}

// reshape: addresses and phone numbers again, on what was rendered: a name removed from
// beside a number can leave a phone shape that was not one before.
func reshape(out string) string {
	sp := &spanSet{}
	c := &scan{s: out, r: rawReading(out), out: sp}
	c.shapes()
	if len(sp.spans) == 0 {
		return out
	}
	r, _ := render(out, sp, true)
	return r
}

// Scrub returns at most limit runes of text with secrets, addresses, phone numbers and the
// denylist's identities and vendors removed. With no denylist (nil, as a failed LoadDenylist
// leaves it) nothing is sent: the output is the cut marker alone. NoDenylist scrubs without one.
func Scrub(text string, d *Denylist, limit int) string {
	if d == nil {
		return Cut
	}
	return settled(text, func(t string) (string, bool) {
		window := firstRunes(t, limit+RedactMargin)
		out := renderFixed(window, detectText(window, d, modeScrub), false, func(t string) *spanSet { return detectText(t, d, modeScrub) })
		out = reshape(out)
		res := cut(out, limit, utf8.RuneCountInString(t))
		return res, res != out
	})
}

// Redact returns at most limit runes of text with secrets removed (no shapes, no denylist).
func Redact(text string, limit int) string {
	return settled(text, func(t string) (string, bool) {
		window := firstRunes(t, limit+RedactMargin)
		out := renderFixed(window, detectText(window, NoDenylist, modeRedact), false, func(t string) *spanSet { return detectText(t, NoDenylist, modeRedact) })
		res := cut(out, limit, utf8.RuneCountInString(t))
		return res, res != out
	})
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

// awaitsValue: a word that names a value the next word holds: `name:`, `name=`, a
// credential's flag, a header flag, an auth scheme.
func awaitsValue(word string) bool {
	w := strings.Trim(word, "\"'`{([,")
	if w == "" {
		return false
	}
	if strings.HasSuffix(w, ":") || strings.HasSuffix(w, "=") {
		return true
	}
	if w == "-H" || w == "--header" || authSchemes[strings.ToLower(w)] {
		return true
	}
	// SQL's `IDENTIFIED BY x` and `PASSWORD x`: a receiver reads the marker as the value.
	if strings.EqualFold(w, "by") || strings.EqualFold(w, "password") {
		return true
	}
	// A name and its hidden value glued (`Authorization:<redacted>`): the marker reads as more of that value.
	if k := strings.LastIndexByte(w, ':'); k > 0 && k < len(w)-1 && onlyPlaceholders(w[k+1:]) {
		return true
	}
	if strings.HasPrefix(w, "-") {
		return IsCredentialName(strings.TrimLeft(w, "-")) || len(strings.TrimLeft(w, "-")) == 1
	}
	// A name glued to what was hidden before it (`"<redacted>"'<redacted>'-password`): the name is the word's tail.
	if k := strings.LastIndexAny(w, "\"'`>"); k >= 0 && k < len(w)-1 {
		return awaitsValue(w[k+1:])
	}
	return false
}
