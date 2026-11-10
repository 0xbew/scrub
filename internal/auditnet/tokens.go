package auditnet

import (
	"encoding/json"
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/tokens"
)

// --- vendor tokens: the table's segments walked by the net's own matcher ---------------------------------

type netSegment struct {
	text     string // a fixed text, or "" for a run of chars
	fold     bool
	chars    string
	min, max int
}

type netFormat struct {
	segs   []netSegment
	anchor int  // the first fixed text's index
	glued  bool // read even glued to a word before it (netGluedFormat)
}

// netMaxRun bounds an unbounded run: a token body is never this long, and the walk stays linear.
const netMaxRun = 512

var netFormats = func() []netFormat {
	var table struct {
		Formats []struct {
			Segments []tokens.TokenSegment `json:"segments"`
		} `json:"formats"`
	}
	if err := json.Unmarshal(tokens.TokensJSON, &table); err != nil {
		panic("scrub: tokens.json is unreadable: " + err.Error())
	}
	var out []netFormat
	for _, f := range table.Formats {
		nf := netFormat{anchor: -1, glued: netGluedFormat(f.Segments)}
		for i, seg := range f.Segments {
			if seg.Text != nil {
				t := *seg.Text
				if seg.IgnoreCase {
					t = lex.AsciiLower(t)
				}
				nf.segs = append(nf.segs, netSegment{text: t, fold: seg.IgnoreCase})
				if nf.anchor < 0 {
					nf.anchor = i
				}
				continue
			}
			ns := netSegment{chars: *seg.Chars, max: netMaxRun}
			if seg.Min != nil {
				ns.min = *seg.Min
			}
			if seg.Max != nil {
				ns.max = *seg.Max
			}
			nf.segs = append(nf.segs, ns)
		}
		if nf.anchor >= 0 {
			out = append(out, nf)
		}
	}
	return out
}()

// netGluedVendors and netGluedFormat: the formats distinctive enough to read glued to a word before them, the
// scrubber's own rule restated (a prefix of five or more characters holding `_` or `-`, or of four opening with two
// capitals, in one case, with no `.` `/` `~` `=`; fixed runs between and a last run of ten or more; or one of the
// vendor prefixes below at twenty characters or more).
var netGluedVendors = lex.SetOf("xoxb-", "xoxp-", "sk_live_", "rk_live_", "glpat-")

func netGluedFormat(segs []tokens.TokenSegment) bool {
	p := segs[0].Text
	if p == nil || segs[0].IgnoreCase || strings.ContainsAny(*p, "./~=") {
		return false
	}
	t := *p
	if netGluedVendors[t] {
		n := 0
		for _, g := range segs {
			if g.Text != nil {
				n += len(*g.Text)
			} else if g.Min != nil {
				n += *g.Min
			}
		}
		return n >= 20
	}
	if !(len(t) >= 5 && strings.ContainsAny(t, "_-") || len(t) == 4 && lex.IsUpperASCII(t[0]) && lex.IsUpperASCII(t[1])) {
		return false
	}
	last := segs[len(segs)-1]
	if last.Chars == nil || last.Min == nil || *last.Min < 10 {
		return false
	}
	for _, g := range segs[1 : len(segs)-1] {
		if g.Chars != nil && (g.Min == nil || g.Max == nil || *g.Min != *g.Max) {
			return false
		}
	}
	return true
}

// netToken: a vendor token in s, by its fixed text and then its runs on either side.
func netToken(s string) bool {
	lowered := lex.AsciiLower(s)
	for _, f := range netFormats {
		a := f.segs[f.anchor]
		hay := s
		if a.fold {
			hay = lowered
		}
		for k := strings.Index(hay, a.text); k >= 0; {
			if (f.anchor > 0 || f.glued || netWordStart(s, k)) && netBack(f.segs[:f.anchor], s, k) &&
				netForward(f.segs[f.anchor+1:], s, lowered, k+len(a.text)) {
				return true
			}
			next := strings.Index(hay[k+1:], a.text)
			if next < 0 {
				break
			}
			k += 1 + next
		}
	}
	return false
}

// netWordStart: a token's fixed text opens a word at k, or follows a one-letter option or a written escape glued
// to it (`-dghp_…`, `\nghp_…`): `disk-…` holds `sk-` but no token.
func netWordStart(s string, k int) bool {
	if k == 0 || !lex.IsAlnumASCII(s[k-1]) {
		return true
	}
	return k >= 2 && (s[k-2] == '-' || s[k-2] == '\\') && (k == 2 || !lex.IsAlnumASCII(s[k-3]))
}

func netRun(chars string, s string, i, limit int) int {
	n := 0
	for i+n < len(s) && n < limit && strings.IndexByte(chars, s[i+n]) >= 0 {
		n++
	}
	return n
}

func netForward(segs []netSegment, s, lowered string, i int) bool {
	if len(segs) == 0 {
		return true
	}
	g := segs[0]
	if g.text != "" {
		hay := s
		if g.fold {
			hay = lowered
		}
		return strings.HasPrefix(hay[i:], g.text) && netForward(segs[1:], s, lowered, i+len(g.text))
	}
	n := netRun(g.chars, s, i, g.max)
	for c := n; c >= g.min; c-- {
		if netForward(segs[1:], s, lowered, i+c) {
			return true
		}
	}
	return false
}

// netBack: the runs before the fixed text, read backwards from end (they are runs only: the anchor is the first
// fixed text).
func netBack(segs []netSegment, s string, end int) bool {
	if len(segs) == 0 {
		return true
	}
	g := segs[len(segs)-1]
	n := 0
	for end-n > 0 && n < g.max && strings.IndexByte(g.chars, s[end-n-1]) >= 0 {
		n++
	}
	for c := n; c >= g.min; c-- {
		if netBack(segs[:len(segs)-1], s, end-c) {
			return true
		}
	}
	return false
}

// --- what is left of a token another rule hid in part ------------------------------------------------------

const netLong = "<long-token>"

// netTokenRemnant: the long-run rule hid a token's body but not its fixed text, or not all of it: the fixed text,
// or four or more of its first characters standing as a word's start, glued to the placeholder (`glpat-<long-token>`,
// `hooks.slack.<long-token>`); or random letters and digits, `=` padding or a run of digits glued to it
// (`<long-token>-aMvrj2QQvE`, `<long-token>========`).
func netTokenRemnant(s string) bool {
	for k := strings.Index(s, netLong); k >= 0; {
		if netAnchorBefore(s, k) || netGluedPiece(s, k+len(netLong)) || netFormatInto(s, k) {
			return true
		}
		next := strings.Index(s[k+1:], netLong)
		if next < 0 {
			break
		}
		k += 1 + next
	}
	return false
}

func netAnchorBefore(s string, k int) bool {
	for _, f := range netFormats {
		a := f.segs[f.anchor].text
		if f.anchor > 0 || len(a) < 3 {
			continue
		}
		for n := len(a); n >= 4 || n == len(a); n-- {
			if n > k {
				continue
			}
			t := s[k-n : k]
			if f.segs[f.anchor].fold {
				t = lex.AsciiLower(t)
			}
			if t == a[:n] && (k-n == 0 || !lex.IsAlnumASCII(s[k-n-1])) {
				return true
			}
			if n <= 4 {
				break
			}
		}
	}
	return false
}

// netFormatInto: a format's fixed text, the runs before it and some of its body, eight characters or more in all,
// running into the placeholder at k (`2628738251627872:AERX9_-<long-token>`).
func netFormatInto(s string, k int) bool {
	lo := k - 80
	if lo < 0 {
		lo = 0
	}
	window := s[lo:k]
	lowered := lex.AsciiLower(window)
	for _, f := range netFormats {
		a := f.segs[f.anchor]
		hay := window
		if a.fold {
			hay = lowered
		}
		for at := strings.LastIndex(hay, a.text); at >= 0; {
			start := lo + at
			// The token starts a word (`disk-encryption-` holds `sk-` but is no token), its runs before the fixed text
			// as long as the format allows.
			for b := start; b >= lo; b-- {
				if (b == 0 || !lex.IsAlnumASCII(s[b-1]) || f.glued) && k-b >= 8 && netBackTo(f.segs[:f.anchor], s, start, b) &&
					netForwardTo(f.segs[f.anchor+1:], s, start+len(a.text), k) {
					return true
				}
				if f.anchor == 0 {
					break
				}
			}
			if at == 0 {
				break
			}
			at = strings.LastIndex(hay[:at], a.text)
		}
	}
	return false
}

// netBackTo: the runs before the fixed text fill s[b:end] exactly.
func netBackTo(segs []netSegment, s string, end, b int) bool {
	if len(segs) == 0 {
		return b == end
	}
	g := segs[len(segs)-1]
	for c := 0; c <= g.max && end-c >= b; c++ {
		if c > 0 && strings.IndexByte(g.chars, s[end-c]) < 0 {
			break
		}
		if c >= g.min && netBackTo(segs[:len(segs)-1], s, end-c, b) {
			return true
		}
	}
	return false
}

// netForwardTo: the segments after the fixed text, read from i, reach k inside a run or at a run's start.
func netForwardTo(segs []netSegment, s string, i, k int) bool {
	if i == k {
		return true
	}
	if len(segs) == 0 || i > k {
		return false
	}
	g := segs[0]
	if g.text != "" {
		if k-i < len(g.text) {
			return false
		}
		t := s[i : i+len(g.text)]
		if g.fold {
			t = lex.AsciiLower(t)
		}
		return t == g.text && netForwardTo(segs[1:], s, i+len(g.text), k)
	}
	n := netRun(g.chars, s[:k], i, g.max)
	if i+n == k {
		return true
	}
	for c := n; c >= g.min; c-- {
		if netForwardTo(segs[1:], s, i+c, k) {
			return true
		}
	}
	return false
}

// NetRemnants: each random piece glued after a long-run placeholder (netGluedPiece), the glue with it: the scrubber's
// re-read hides it (`…/<long-token>-e8RezSK_sw0…` is the rest of one token the long-run rule took part of).
func NetRemnants(s string, emit func(lo, hi int)) {
	for k := strings.Index(s, netLong); k >= 0; {
		i := k + len(netLong)
		if netGluedPiece(s, i) {
			e := i
			for e < len(s) && strings.IndexByte("-_.~:", s[e]) >= 0 {
				e++
			}
			// The token's further parts glued by `-` or `_` go with it.
			for e < len(s) && (lex.IsAlnumASCII(s[e]) || strings.IndexByte("+=-_", s[e]) >= 0) {
				e++
			}
			emit(i, e)
		}
		next := strings.Index(s[i:], netLong)
		if next < 0 {
			return
		}
		k = i + next
	}
}

// netGluedPiece: right after the placeholder ending at i, glue (`-` `_` `.` `~` `:`) then a piece that reads random
// (letters and digits, base64's `+` among them, switching between lower case, upper case and digits twice
// or more and not words written as code, or twelve digits), or six or more `=`. A word (`-Final`, `.Config1`,
// `.toString`) is no piece.
func netGluedPiece(s string, i int) bool {
	if strings.HasPrefix(s[i:], "======") {
		return true
	}
	j := i
	for j < len(s) && strings.IndexByte("-_.~:", s[j]) >= 0 {
		j++
	}
	if j == i {
		return false
	}
	e := j
	for e < len(s) && (lex.IsAlnumASCII(s[e]) || s[e] == '+') {
		e++
	}
	return netRandomish(s[j:e])
}

func netRandomish(p string) bool {
	n, digits, switches, prev := 0, 0, 0, 0
	for i := 0; i < len(p); i++ {
		c := netClass(p[i])
		if c == 0 {
			continue
		}
		n++
		if c == 3 {
			digits++
		}
		if prev != 0 && c != prev {
			switches++
		}
		prev = c
	}
	return n >= 5 && switches >= 2 && !netWordLike(p) && !netHexID(p) || digits == n && n >= 12
}

// netHexID: lower-case hex, as the rest of a UUID or a short commit id is written (`-054918489b61`, `..dbc9c2d`).
func netHexID(p string) bool {
	for i := 0; i < len(p); i++ {
		if c := p[i]; !(lex.IsDigitASCII(c) || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// netWordLike: words written as code (`toString`, `Release2024Q4`, `Config1`, `requestId`): every capital is
// followed by a lower-case letter, a digit or the end, and every run of lower-case letters is two or more long.
func netWordLike(p string) bool {
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case lex.IsUpperASCII(c):
			if i+1 < len(p) && lex.IsUpperASCII(p[i+1]) {
				return false
			}
		case lex.IsLowerASCII(c):
			if i == 0 || !lex.IsLowerASCII(p[i-1]) {
				j := i
				for j < len(p) && lex.IsLowerASCII(p[j]) {
					j++
				}
				// One letter after a capital is a short word (`requestId`, `getById`).
				if j-i < 2 && !(j-i == 1 && i > 0 && (p[i-1:i+1] == "Id" || p[i-1:i+1] == "By")) {
					return false
				}
			}
		case lex.IsDigitASCII(c):
		default:
			return false
		}
	}
	return true
}
