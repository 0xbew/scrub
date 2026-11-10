package scrub

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The audit's safety net (contract rule 9): its own checks for what the scrubber's detectors hide, so a
// detector that goes blind does not take the audit with it. Nothing here calls a detector or the scan's rules
// (tokenSpans, the long-run, address and phone readers, identityMatches); each check is its own and narrower
// than the detector it backs, so the net refuses only what the scrubber hides when it works. A hit is a
// refusal only: the scrubber's own re-read (locateLive) never sees the net, so it never changes an output.

// netHits: the rules the net finds in the readings of the texts.
func netHits(readings []*reading, d *Denylist) map[string]bool {
	found := map[string]bool{}
	for _, r := range readings {
		s := r.text
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
		if r.joined {
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
		if !r.pctd && !found["phone"] && netPhone(s) {
			found["phone"] = true
		}
		if d != nil {
			for _, id := range d.identities {
				if !found[id.rule] && netIdentity(id, s) {
					found[id.rule] = true
				}
			}
		}
	}
	return found
}

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
			Segments []tokenSegment `json:"segments"`
		} `json:"formats"`
	}
	if err := json.Unmarshal(tokensJSON, &table); err != nil {
		panic("scrub: tokens.json is unreadable: " + err.Error())
	}
	var out []netFormat
	for _, f := range table.Formats {
		nf := netFormat{anchor: -1, glued: netGluedFormat(f.Segments)}
		for i, seg := range f.Segments {
			if seg.Text != nil {
				t := *seg.Text
				if seg.IgnoreCase {
					t = asciiLower(t)
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
var netGluedVendors = setOf("xoxb-", "xoxp-", "sk_live_", "rk_live_", "glpat-")

func netGluedFormat(segs []tokenSegment) bool {
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
	if !(len(t) >= 5 && strings.ContainsAny(t, "_-") || len(t) == 4 && isUpperASCII(t[0]) && isUpperASCII(t[1])) {
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
	lowered := asciiLower(s)
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
	if k == 0 || !isAlnumASCII(s[k-1]) {
		return true
	}
	return k >= 2 && (s[k-2] == '-' || s[k-2] == '\\') && (k == 2 || !isAlnumASCII(s[k-3]))
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
				t = asciiLower(t)
			}
			if t == a[:n] && (k-n == 0 || !isAlnumASCII(s[k-n-1])) {
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
	lowered := asciiLower(window)
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
				if (b == 0 || !isAlnumASCII(s[b-1]) || f.glued) && k-b >= 8 && netBackTo(f.segs[:f.anchor], s, start, b) &&
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
			t = asciiLower(t)
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

// netRemnants: each random piece glued after a long-run placeholder (netGluedPiece), the glue with it: the scrubber's
// re-read hides it (`…/<long-token>-e8RezSK_sw0…` is the rest of one token the long-run rule took part of).
func netRemnants(s string, emit func(lo, hi int)) {
	for k := strings.Index(s, netLong); k >= 0; {
		i := k + len(netLong)
		if netGluedPiece(s, i) {
			e := i
			for e < len(s) && strings.IndexByte("-_.~:", s[e]) >= 0 {
				e++
			}
			// The token's further parts glued by `-` or `_` go with it.
			for e < len(s) && (isAlnumASCII(s[e]) || strings.IndexByte("+=-_", s[e]) >= 0) {
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
	for e < len(s) && (isAlnumASCII(s[e]) || s[e] == '+') {
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
		if c := p[i]; !(isDigitASCII(c) || c >= 'a' && c <= 'f') {
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
		case isUpperASCII(c):
			if i+1 < len(p) && isUpperASCII(p[i+1]) {
				return false
			}
		case isLowerASCII(c):
			if i == 0 || !isLowerASCII(p[i-1]) {
				j := i
				for j < len(p) && isLowerASCII(p[j]) {
					j++
				}
				// One letter after a capital is a short word (`requestId`, `getById`).
				if j-i < 2 && !(j-i == 1 && i > 0 && (p[i-1:i+1] == "Id" || p[i-1:i+1] == "By")) {
					return false
				}
			}
		case isDigitASCII(c):
		default:
			return false
		}
	}
	return true
}

// --- long random runs ---------------------------------------------------------------------------------------

const (
	netMinRun = 32
	// A random run switches between lower case, upper case and digits at about every other character; words
	// written as code (`CredentialProviderFactory2024`) switch once a word.
	netMinSwitchRate = 0.3
)

func netRunChar(c byte) bool { return isAlnumASCII(c) || c == '+' || c == '/' }

// netLongRun: a run of 32 or more letters, digits, `+` and `/` that holds all three of lower case, upper case
// and digits and switches between them like random text does.
func netLongRun(s string) bool {
	for i := 0; i < len(s); {
		if !netRunChar(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && netRunChar(s[j]) {
			j++
		}
		if j-i >= netMinRun && netRandom(s[i:j]) {
			return true
		}
		i = j
	}
	return false
}

func netClass(c byte) int {
	switch {
	case isLowerASCII(c):
		return 1
	case isUpperASCII(c):
		return 2
	case isDigitASCII(c):
		return 3
	}
	return 0
}

func netRandom(run string) bool {
	// Words written as code, joined by `/` or not (`Hello/World/FooBar/Corge1`), are a path or a name.
	words := true
	for _, part := range strings.Split(run, "/") {
		if part != "" && !netWordLike(part) {
			words = false
			break
		}
	}
	if words {
		return false
	}
	seen := [4]bool{}
	switches, letters := 0, 0
	prev := 0
	for i := 0; i < len(run); i++ {
		c := netClass(run[i])
		if c == 0 {
			prev = 0
			continue
		}
		seen[c] = true
		letters++
		if prev != 0 && c != prev {
			switches++
		}
		prev = c
	}
	return seen[1] && seen[2] && seen[3] && letters > 0 && float64(switches) >= netMinSwitchRate*float64(letters)
}

// --- a JWT's remnants ---------------------------------------------------------------------------------------

// netJWTRemnant: a JWT whose parts other rules hid in pieces, so its `eyJ` is gone: three or more dot-joined
// parts of base64url and placeholders, two placeholders among them (a JWT's header and payload are each long
// enough for the long-run rule) or its `eyJ` still opening it, and a piece that reads random still standing
// (`<long-token>.<long-token>-Zq9xK2<long-token>.Tm3-<long-token>`).
func netJWTRemnant(s string) bool {
	const ph = "<long-token>"
	for k := strings.Index(s, ph); k >= 0; {
		lo, hi := k, k+len(ph)
		for {
			if lo > 0 && netJWTChar(s[lo-1]) {
				lo--
			} else if lo >= len(ph) && s[lo-len(ph):lo] == ph {
				lo -= len(ph)
			} else {
				break
			}
		}
		for {
			if hi < len(s) && netJWTChar(s[hi]) {
				hi++
			} else if strings.HasPrefix(s[hi:], ph) {
				hi += len(ph)
			} else {
				break
			}
		}
		w := s[lo:hi]
		if strings.Count(w, ".") >= 2 && (strings.Count(w, ph) >= 2 || strings.HasPrefix(w, "eyJ")) &&
			netRandomPiece(strings.ReplaceAll(w, ph, " ")) {
			return true
		}
		next := strings.Index(s[hi:], ph)
		if next < 0 {
			break
		}
		k = hi + next
	}
	return false
}

func netJWTChar(c byte) bool { return isAlnumASCII(c) || c == '-' || c == '_' || c == '.' }

// netRandomPiece: a run of five or more base64url characters and dots between the placeholders, of which three or
// more are letters and digits holding two of lower case, upper case and digits (`.IvSt-`, `-igNMo`).
func netRandomPiece(w string) bool {
	for i := 0; i < len(w); {
		if !netJWTChar(w[i]) {
			i++
			continue
		}
		j := i
		alnum := 0
		seen := [4]bool{}
		for j < len(w) && netJWTChar(w[j]) {
			if isAlnumASCII(w[j]) {
				alnum++
				seen[netClass(w[j])] = true
			}
			j++
		}
		kinds := 0
		for _, b := range seen[1:] {
			if b {
				kinds++
			}
		}
		if j-i >= 5 && alnum >= 3 && kinds >= 2 {
			return true
		}
		i = j
	}
	return false
}

// --- addresses and phone numbers ---------------------------------------------------------------------------

var netEmailRx = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

// netEmail: an address whose last label is two or more letters standing as a word's end.
func netEmail(s string) bool {
	for _, m := range netEmailRx.FindAllStringIndex(s, -1) {
		if m[1] >= len(s) || !(isAlnumASCII(s[m[1]]) || s[m[1]] == '-') {
			return true
		}
	}
	return false
}

var (
	netNANPRx = regexp.MustCompile(`(?:\+?1[ .-]?)?(?:\(\d{3}\) ?|\d{3}[ .-])\d{3}[ .-]\d{4}`)
	netIntlRx = regexp.MustCompile(`\+[1-9]\d{0,2}(?:[ .-]?\d{2,6}){1,5}`)
	// A date after a diff row's `+` (`+2026-10-25 14`) is no number.
	netDateRx = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
)

// netPhone: a North American number in its written forms, or `+` and a country code with groups of digits
// (8 to 15 digits, no date), standing apart from words, `.`, `+` and `-` on either side.
func netPhone(s string) bool {
	texts := []string{s}
	// A diff document's rows are read without their marker, as the scrubber reads a diff's sides; a diff quoted
	// inside other text (a test's string) is read as written, where `+(415) …` is a marker and a row, no number.
	if strings.HasPrefix(s, "diff --git ") || strings.HasPrefix(s, "--- ") || strings.HasPrefix(s, "@@ -") {
		var b strings.Builder
		for _, ln := range strings.SplitAfter(s, "\n") {
			if ln != "" && strings.IndexByte("+- ", ln[0]) >= 0 {
				ln = ln[1:]
			}
			b.WriteString(ln)
		}
		texts = append(texts, b.String())
	}
	for _, t := range texts {
		for _, m := range netNANPRx.FindAllStringIndex(t, -1) {
			if netPhoneApart(t, m[0], m[1]) {
				return true
			}
		}
		for _, m := range netIntlRx.FindAllStringIndex(t, -1) {
			digits := 0
			for i := m[0]; i < m[1]; i++ {
				if isDigitASCII(t[i]) {
					digits++
				}
			}
			if digits >= 8 && digits <= 15 && netPhoneApart(t, m[0], m[1]) && !netDateRx.MatchString(t[m[0]:m[1]]) {
				return true
			}
		}
	}
	return false
}

func netPhoneApart(s string, lo, hi int) bool {
	if lo > 0 {
		if c := s[lo-1]; isAlnumASCII(c) || c == '_' || c == '.' || c == '+' || c == '-' {
			return false
		}
	}
	return hi >= len(s) || !(isAlnumASCII(s[hi]) || s[hi] == '_' || s[hi] == '-')
}

// --- the denylist's identities ------------------------------------------------------------------------------

// netIdentity: the identity's pattern anywhere in s; a literal one with no letter or digit, in any script, on
// either side.
func netIdentity(id identity, s string) bool {
	for at := 0; at < len(s); {
		m := id.rx.FindStringIndex(s[at:])
		if m == nil {
			return false
		}
		lo, hi := at+m[0], at+m[1]
		if hi > lo && (!id.literal || !netAlnumRune(s, lo, true) && !netAlnumRune(s, hi, false)) {
			return true
		}
		// Glued to a letter or digit: a later match, or a shorter one a rune on, may stand.
		_, sz := utf8.DecodeRuneInString(s[lo:])
		if sz == 0 {
			sz = 1
		}
		at = lo + sz
	}
	return false
}

func netAlnumRune(s string, i int, before bool) bool {
	var r rune
	if before {
		if i <= 0 {
			return false
		}
		r, _ = utf8.DecodeLastRuneInString(s[:i])
	} else {
		if i >= len(s) {
			return false
		}
		r, _ = utf8.DecodeRuneInString(s[i:])
	}
	return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.Is(unicode.Mn, r)
}

// --- cookies, program options and colon values --------------------------------------------------------------

// netCookie: a Cookie or Set-Cookie header holding a pair (`name=value`) whose value is not a placeholder.
func netCookie(s string) bool {
	lowered := asciiLower(s)
	for k := strings.Index(lowered, "cookie:"); k >= 0; {
		if k == 0 || !isAlnumASCII(s[k-1]) || strings.HasSuffix(lowered[:k], "set-") {
			end := lineEnd(s, k)
			if q := netQuoteBefore(s, k); q != 0 {
				if e := strings.IndexByte(s[k:end], q); e >= 0 {
					end = k + e
				}
			}
			if netPairLive(s[k+len("cookie:") : end]) {
				return true
			}
			k = end - 1 // a later header on the line was read as part of this one's pairs
		}
		next := strings.Index(lowered[k+1:], "cookie:")
		if next < 0 {
			break
		}
		k += 1 + next
	}
	return false
}

// netQuoteBefore: the quote that opens the header's word (`-H "Cookie: …"`), if any.
func netQuoteBefore(s string, k int) byte {
	for i := k - 1; i >= 0 && s[i] != '\n'; i-- {
		switch s[i] {
		case '"', '\'':
			return s[i]
		case ' ', '\t':
			return 0
		}
	}
	return 0
}

// netPairLive: the header's `name=value` pairs, each closed by `;` but the last, one of them with a value that is
// not placeholders; the first word that is no pair ends the header (the line's text after it is not the cookie's).
func netPairLive(v string) bool {
	for i := 0; i < len(v); {
		for i < len(v) && (v[i] == ' ' || v[i] == '\t') {
			i++
		}
		eq := i
		for eq < len(v) && v[eq] != '=' && v[eq] != ';' && !isSpaceByte(v[eq]) {
			eq++
		}
		if eq == i || eq >= len(v) || v[eq] != '=' {
			return false
		}
		e := eq + 1
		for e < len(v) && v[e] != ';' && !isSpaceByte(v[e]) {
			e++
		}
		if val := v[eq+1 : e]; val != "" && !onlyPlaceholders(val) {
			return true
		}
		if e >= len(v) || v[e] != ';' {
			return false
		}
		i = e + 1
	}
	return false
}

// netPrograms: a program whose short option holds a password, and whether the value may also stand apart.
var netPrograms = []struct {
	name, option string
	apart        bool
}{
	{"mysql", "-p", false}, {"mysqldump", "-p", false}, {"mysqladmin", "-p", false}, {"mysqlimport", "-p", false},
	{"mysqlcheck", "-p", false}, {"mysqlshow", "-p", false}, {"mariadb", "-p", false}, {"mariadb-dump", "-p", false},
	{"sshpass", "-p", true}, {"redis-cli", "-a", true},
}

// netProgramOption: one of netPrograms, then on its command (to `;`, `|`, `&` or the line's end) its option with
// a value glued to it (or after a blank, where the program allows it) that is not a placeholder.
func netProgramOption(s string) bool {
	for _, p := range netPrograms {
		for k := strings.Index(s, p.name); k >= 0; {
			after := k + len(p.name)
			if (k == 0 || !netProgChar(s[k-1])) && (after >= len(s) || !netProgChar(s[after])) {
				end := after
				for end < len(s) && strings.IndexByte(";|&\n", s[end]) < 0 {
					end++
				}
				if netOptionLive(s[after:end], p.option, p.apart) {
					return true
				}
				k = end - 1 // the program again on the same command: its options were just read
			}
			next := strings.Index(s[k+1:], p.name)
			if next < 0 {
				break
			}
			k += 1 + next
		}
	}
	return false
}

func netProgChar(c byte) bool { return isAlnumASCII(c) || c == '-' || c == '_' || c == '.' }

func netOptionLive(cmd, option string, apart bool) bool {
	f := strings.Fields(cmd)
	for i := 0; i < len(f); i++ {
		w := strings.Trim(f[i], "\"'")
		if !strings.HasPrefix(w, "-") {
			// The program's first plain argument (a database, a host command) ends its own options: what follows
			// on the line is another program's or prose (`find . -print`).
			return false
		}
		if w == option {
			if apart && i+1 < len(f) && netOptionValue(strings.Trim(f[i+1], "\"'")) {
				return true
			}
		} else if strings.HasPrefix(w, option) && !strings.HasPrefix(w, "--") {
			if netOptionValue(strings.Trim(w[len(option):], "\"'")) {
				return true
			}
			continue
		}
		// An option that takes its value apart (`-u app`, `--port 3306`) skips it.
		if (len(w) == 2 || strings.HasPrefix(w, "--") && !strings.Contains(w, "=")) && i+1 < len(f) && !strings.HasPrefix(f[i+1], "-") {
			i++
		}
	}
	return false
}

// netOptionValue: an option's value that is not another option, a reference (`$PW`, `%s`, `{pw}`), placeholders, or
// prose and markup around a program's name (“ `openssl “, `(see`), or a written escape (`\n`).
func netOptionValue(v string) bool {
	return v != "" && strings.IndexByte("-$%{<`()[],;\\", v[0]) < 0 && !onlyPlaceholders(v)
}

// netNamedValue: a credential's name standing as a word, then `:` and a blank (or a quoted name and `:`), or a
// blank, `=` and a blank, then one word that reads as a value: letters and digits mixed, or letters only and long.
// Letters only count from eight letters after a name whose last word is the credential itself (`password`,
// `DB_PASSWORD`, `api_key`), at a YAML line's start for any name, and from thirteen otherwise.
func netNamedValue(s string) bool {
	// The line's last `{` and `}` so far: a name after an unclosed `{` stands in a flow mapping.
	lastOpen, lastClose := -1, -1
	for p := 0; p < len(s); p++ {
		c := s[p]
		switch c {
		case '\n':
			lastOpen, lastClose = -1, -1
		case '{':
			lastOpen = p
		case '}':
			lastClose = p
		}
		if c != ':' && c != '=' {
			continue
		}
		q := p
		if c == '=' {
			if p+1 < len(s) && (s[p+1] == '=' || s[p+1] == '~') {
				continue
			}
			for q > 0 && (s[q-1] == ' ' || s[q-1] == '\t') {
				q--
			}
			if q == p || p+1 >= len(s) || (s[p+1] != ' ' && s[p+1] != '\t') {
				continue // `NAME=value` is the assignment check's
			}
		}
		quoted := c == ':' && q > 0 && (s[q-1] == '"' || s[q-1] == '\'')
		if quoted {
			q--
		}
		n := q
		for n > 0 && (isAlnumASCII(s[n-1]) || s[n-1] == '_' || s[n-1] == '-') {
			n--
		}
		if n == q {
			continue
		}
		name := s[n:q]
		if quoted {
			if n == 0 || s[n-1] != s[q] {
				continue
			}
			n--
		}
		if n > 0 && (isAlnumASCII(s[n-1]) || strings.IndexByte(".$@#/\\", s[n-1]) >= 0) {
			continue // a member, a variable or a path: not a name standing as a word
		}
		if !IsCredentialName(name) {
			continue
		}
		v := p + 1
		for v < len(s) && (s[v] == ' ' || s[v] == '\t') {
			v++
		}
		if c == ':' && v == p+1 && !quoted {
			continue // `name:value` with no blank is a URL's scheme or a time as often as a value
		}
		yaml := c == ':' && netLineHead(s, n)
		flow := c == ':' && lastOpen > lastClose
		e := v
		for e < len(s) && e-v < netMaxWord && !isSpaceByte(s[e]) && !(flow && (s[e] == ',' || s[e] == '}')) {
			e++
		}
		// A JSON key's value is a string; unquoted it is a number, a literal or no JSON at all.
		if quoted && (v >= len(s) || s[v] != '"' && s[v] != '\'' && s[v] != '\\') {
			continue
		}
		if netValueWord(s[v:e], netStrongName(name) || yaml) {
			return true
		}
	}
	return false
}

var netStrongKeyOwners = setOf("api", "secret", "private", "access")

// netMaxWord bounds the word read after a name, so a long line of names glued to values stays linear.
const netMaxWord = 256

// netStrongName: a name whose last word is the credential itself.
func netStrongName(name string) bool {
	words := nameWords(name)
	if len(words) == 0 {
		return false
	}
	last := strings.ToLower(words[len(words)-1])
	if last == "key" {
		return len(words) > 1 && netStrongKeyOwners[strings.ToLower(words[len(words)-2])]
	}
	for _, e := range []string{"password", "passwd", "passphrase", "pwd", "secret", "token", "apikey"} {
		if strings.HasSuffix(last, e) {
			return true
		}
	}
	return false
}

// netLineHead: a name first on its line after blanks, an opening quote, a diff row's marker or a YAML list's `- `,
// or after a flow mapping's `{` or `,`.
func netLineHead(s string, n int) bool {
	i := n
	for i > 0 && strings.IndexByte(" \t\"'\\", s[i-1]) >= 0 {
		i--
	}
	if i > 0 && (s[i-1] == '{' || s[i-1] == ',') {
		return true
	}
	if i > 0 && s[i-1] == '-' {
		i--
		for i > 0 && strings.IndexByte(" \t\"'\\", s[i-1]) >= 0 {
			i--
		}
	}
	if i > 0 && (s[i-1] == '+' || s[i-1] == '-') && (i == 1 || s[i-2] == '\n') {
		i--
	}
	return i == 0 || s[i-1] == '\n'
}

// netProse: words a YAML or a sentence puts after a credential's name that hold no value.
var netProse = setOf("required", "optional", "undefined", "changeme", "redacted", "placeholder", "password",
	"passwords", "secret", "secrets", "token", "tokens", "example", "missing", "invalid", "expired", "disabled",
	"enabled", "string", "boolean", "integer", "nullable", "default", "unknown", "rotated", "provided", "supplied",
	"generated", "configured", "available", "required", "returned", "omitted")

// netValueWord: the word after a name, its wrapping and closing punctuation aside, reads as a value: not a
// placeholder, a reference or code, and either letters mixed with digits, or letters only and long.
func netValueWord(w string, strong bool) bool {
	for _, open := range []string{"**", "\\\"", "\"", "'", "`", "(", "["} {
		w = strings.TrimPrefix(w, open)
	}
	w = strings.TrimRight(w, ".,;:!?)]}>*`\"'\\")
	if w == "" || onlyPlaceholders(w) || strings.ContainsAny(w[:1], "$%{|>&*!~<[") || netProse[strings.ToLower(w)] {
		return false
	}
	letters, digits, upper, seps := 0, 0, 0, 0
	for i := 0; i < len(w); i++ {
		switch ch := w[i]; {
		case isDigitASCII(ch):
			digits++
		case isLowerASCII(ch):
			letters++
		case isUpperASCII(ch):
			letters++
			if i > 0 {
				upper++
			}
		case ch == '-' || ch == '_' || ch == '+' || ch == '/' || ch == '=' || ch == '.' || ch == '~':
			seps++
		default:
			return false // a call, a type or markup: code, not a value
		}
	}
	switch {
	case digits > 0 && letters > 0:
		return letters+digits >= 6
	case digits > 0 || seps > 0:
		return false // a count, or letters joined as an identifier (`secret_scope`, `self.token`)
	case isUpperASCII(w[0]):
		return false // a type or a name (`secret: SecretStr`, `token: Optional`)
	case strong:
		return letters >= 8
	}
	// Letters only, after any name: long, and lower case throughout or capitals at random, not a type's humps.
	return letters >= 13 && (upper == 0 || upper*4 >= letters)
}
