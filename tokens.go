package scrub

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Vendor token formats: a fixed prefix and the body after it, wherever they stand. The table
// is generated from gitleaks' catalogue (tokens.json), plus the rows its `local` map names and explains.

//go:embed tokens.json
var tokensJSON []byte

type tokenFormat struct {
	rule string
	key  string // the first fixed text, lowercased: a text without it cannot hold the token
	rx   *regexp.Regexp
}

type tokenSegment struct {
	Text       *string `json:"text"`
	IgnoreCase bool    `json:"ignore_case"`
	Chars      *string `json:"chars"`
	Min        *int    `json:"min"`
	Max        *int    `json:"max"`
}

var (
	tokenFormats  []tokenFormat
	identPrefixes []string
)

const contRx = `(?:\\\r?\n)*`

func charClass(chars string) string {
	var b strings.Builder
	b.WriteByte('[')
	for _, c := range chars {
		if c < 128 && isAlnumASCII(byte(c)) {
			b.WriteRune(c)
		} else {
			b.WriteByte('\\')
			b.WriteRune(c)
		}
	}
	b.WriteByte(']')
	return b.String()
}

func init() {
	var table struct {
		Formats []struct {
			ID       string         `json:"id"`
			Segments []tokenSegment `json:"segments"`
		} `json:"formats"`
	}
	if err := json.Unmarshal(tokensJSON, &table); err != nil {
		panic("scrub: tokens.json is unreadable: " + err.Error())
	}
	prefixes := map[string]bool{}
	for _, f := range table.Formats {
		var b strings.Builder
		// A format that opens with its body (`<id>:A…`, `<14>.atlasv1.…`) has no word start to
		// anchor on: the body may be glued to a word (`bot123456:A…` in a Telegram URL).
		if f.Segments[0].Text != nil && !gluedFormat(f.Segments) {
			b.WriteString(`\b`)
		}
		key := ""
		for i, seg := range f.Segments {
			if seg.Text != nil {
				if key == "" {
					key = strings.ToLower(*seg.Text)
				}
				if i > 0 {
					b.WriteString(contRx)
				}
				t := regexp.QuoteMeta(*seg.Text)
				if seg.IgnoreCase {
					t = "(?i:" + t + ")"
				}
				b.WriteString(t)
				continue
			}
			lo := 0
			if seg.Min != nil {
				lo = *seg.Min
			}
			count := "{" + strconv.Itoa(lo) + ","
			if seg.Max != nil {
				count += strconv.Itoa(*seg.Max)
			}
			count += "}"
			if i == 0 {
				b.WriteString(charClass(*seg.Chars) + count)
				continue
			}
			// A continuation may sit before any character after the prefix.
			b.WriteString("(?:" + contRx + charClass(*seg.Chars) + ")" + count)
		}
		if key == "" {
			panic("scrub: tokens.json: format " + f.ID + " has no fixed text")
		}
		tokenFormats = append(tokenFormats, tokenFormat{rule: f.ID, key: key, rx: regexp.MustCompile(b.String())})
		if f.Segments[0].Text == nil {
			continue
		}
		p := *f.Segments[0].Text
		if f.Segments[0].IgnoreCase {
			p = strings.ToLower(p)
		}
		p = strings.NewReplacer("-", "_", ".", "_").Replace(p)
		if identPrefixRx.MatchString(p) {
			prefixes[p] = true
		}
	}
	for p := range prefixes {
		identPrefixes = append(identPrefixes, p)
	}
	sort.Strings(identPrefixes)
}

// gluedFormat: a format distinctive enough to read even glued to a word before it (`prod_AKIA…`, `x_sk_live_…`,
// `checkedglpat-…`): a prefix of five or more characters holding `_` or `-`, or of four that opens with two capitals
// (`AKIA`, `ASIA`), written in one case, with no `.` `/` `~` `=` that a path or a URL could hold; runs of a fixed
// length between, and a last run of ten or more. The body's exact shape keeps a word that happens to end in the
// prefix from reading as a token.
var gluedVendors = map[string]bool{"xoxb-": true, "xoxp-": true, "sk_live_": true, "rk_live_": true, "glpat-": true}

func gluedFormat(segs []tokenSegment) bool {
	p := segs[0].Text
	if p == nil || segs[0].IgnoreCase || strings.ContainsAny(*p, "./~=") {
		return false
	}
	t := *p
	if gluedVendors[t] {
		// Slack's and Stripe's and GitLab's own prefixes, whatever the runs after them: twenty characters or more.
		n := 0
		for _, seg := range segs {
			if seg.Text != nil {
				n += len(*seg.Text)
			} else if seg.Min != nil {
				n += *seg.Min
			}
		}
		return n >= 20
	}
	switch {
	case len(t) >= 5 && strings.ContainsAny(t, "_-"):
	case len(t) == 4 && isUpperASCII(t[0]) && isUpperASCII(t[1]):
	default:
		return false
	}
	last := segs[len(segs)-1]
	if last.Chars == nil || last.Min == nil || *last.Min < 10 {
		return false
	}
	for _, seg := range segs[1 : len(segs)-1] {
		if seg.Chars != nil && (seg.Min == nil || seg.Max == nil || *seg.Min != *seg.Max) {
			return false
		}
	}
	return true
}

var identPrefixRx = regexp.MustCompile(`^[a-z0-9_]+_$`)

// An escape written out (`\n`, `\x41`, `é`, `\101`) glues its last letter to a prefix
// after it, so `\b` never fires there; this reading blanks each one at the same length.
var writtenEscapeRx = regexp.MustCompile(`\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[A-Za-z])`)

func blankEscapes(s string) string {
	return writtenEscapeRx.ReplaceAllStringFunc(s, func(m string) string { return strings.Repeat(" ", len(m)) })
}

// tokenSpans: every vendor token format's matches in s, and in s with written escapes
// blanked. Overlaps are kept: the union is hidden.
// An option letter attached to its value (`-d` then a token) glues the letter to the token's prefix too; this
// reading blanks a one-letter option at a word's start at the same length.
var shortOptionRx = regexp.MustCompile(`(?:^|[\s'"=(])(-[A-Za-z])[A-Za-z0-9]`)

func blankShortOptions(s string) string {
	b := []byte(s)
	for _, m := range shortOptionRx.FindAllStringSubmatchIndex(s, -1) {
		b[m[2]], b[m[2]+1] = ' ', ' '
	}
	return string(b)
}

func tokenSpans(s string, emit func(lo, hi int)) {
	if off("tokens") {
		return
	}
	lowered := asciiLower(s)
	readings := []string{s}
	if b := blankEscapes(s); b != s {
		readings = append(readings, b)
	}
	if b := blankShortOptions(s); b != s {
		readings = append(readings, b)
	}
	for _, f := range tokenFormats {
		if !strings.Contains(lowered, f.key) {
			continue
		}
		for _, r := range readings {
			for _, m := range f.rx.FindAllStringIndex(r, -1) {
				emit(m[0], m[1])
			}
		}
	}
}

func hasToken(s string) bool {
	found := false
	tokenSpans(s, func(lo, hi int) { found = true })
	return found
}
