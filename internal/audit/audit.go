package audit

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/0xbew/scrub/internal/auditnet"
	"github.com/0xbew/scrub/internal/denylist"
	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/tokens"
	"github.com/0xbew/scrub/internal/vocab"
)

// Hit is an audit rule id. The audit returns rule ids, never the text it found.
type Hit = string

// The audit reads what is about to be sent the way the receiver will: every reading of the
// text (as written, each level of backslash escapes removed, percent-decoded). It shares the
// readings and the classifiers with the scrubber, and nothing else: its names and value
// extents are its own crude code, so one lexer fault cannot blind both.

// Audit returns the rule ids that fire anywhere in text.
func Audit(text string, d *denylist.List) []Hit { return auditTexts([]string{text}, d) }

// AuditValue: Audit over every string in a JSON-shaped value, keys included.
func AuditValue(v any, d *denylist.List) []Hit {
	var texts []string
	stack := []any{v}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch x := item.(type) {
		case string:
			texts = append(texts, x)
		case map[string]any:
			for k, val := range x {
				texts = append(texts, k)
				stack = append(stack, val)
			}
		case []any:
			stack = append(stack, x...)
		}
	}
	return auditTexts(texts, d)
}

// AuditBody: Audit over a JSON document or JSON lines, decoded as the receiver reads them. A
// body that cannot be decoded is `unreadable`: it cannot be shown clean.
func AuditBody(body []byte, d *denylist.List) []Hit {
	if d == nil {
		return []Hit{"denylist:none"}
	}
	if !utf8Valid(body) {
		return []Hit{"unreadable"}
	}
	var values []any
	var one any
	if err := json.Unmarshal(body, &one); err == nil {
		values = append(values, one)
	} else {
		for _, line := range bytes.Split(body, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var v any
			if err := json.Unmarshal(line, &v); err != nil {
				return []Hit{"unreadable"}
			}
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return []Hit{"unreadable"}
	}
	return AuditValue(values, d)
}

func utf8Valid(b []byte) bool { return strings.ToValidUTF8(string(b), "\x00") == string(b) }

func auditTexts(texts []string, d *denylist.List) []Hit {
	// No denylist at all (nil) is a configured list that could not be loaded: refuse. NoDenylist is the choice to go without.
	if d == nil {
		return []Hit{"denylist:none"}
	}
	var hits []Hit
	add := func(rule string, found bool) {
		if found {
			hits = append(hits, rule)
		}
	}
	any := func(f func(string) bool) bool {
		for _, t := range texts {
			if f(t) {
				return true
			}
		}
		return false
	}
	// Every reading of every text, read once; shapes and the denylist skip a joined one.
	var apart, unescaped []string
	var all []*reading.Reading
	for _, t := range texts {
		for _, r := range reading.Of(reading.Raw(t), true) {
			all = append(all, r)
			if !r.Joined {
				apart = append(apart, r.Text)
				if r.Kind != reading.ReadRaw && !r.Pctd {
					unescaped = append(unescaped, r.Text)
				}
			}
		}
	}
	// The safety net's own checks (internal/auditnet): what a blind detector would let through, refused anyway.
	net := auditnet.NetHits(all, d)
	add("email", anyOf(apart, detect.HasEmail) || net["email"])
	// Phones as the scrubber reads them: not percent-decoded, where `+` is a space.
	add("phone", any(hasPhone) || anyOf(unescaped, hasPhone) || net["phone"])
	if d != nil {
		for _, id := range d.Identities {
			id := id
			add(id.Rule, anyOf(apart, func(t string) bool { return denylist.MatchesWithBoundary(id.Rx, t, id.Literal) }) || net[id.Rule])
		}
		for _, v := range d.Vendors {
			v := v
			add(v.Rule, anyOf(apart, func(t string) bool { return v.Rx.MatchString(t) }))
		}
	}
	found := map[string]bool{}
	for rule, hit := range net {
		if hit && strings.HasPrefix(rule, "secret:") {
			found[rule] = true
		}
	}
	for _, t := range texts {
		for _, r := range reading.Of(reading.Raw(t), true) {
			if !found["secret:token-format"] && tokens.HasToken(r.Text) {
				found["secret:token-format"] = true
			}
			if !found["secret:jwt"] && hasJWT(r.Text) {
				found["secret:jwt"] = true
			}
			if !r.Joined && !found["secret:long-run"] && detect.HasLongRun(r) {
				found["secret:long-run"] = true
			}
			a := &auditor{r: r, s: r.Text, pct: r.Pct, found: found}
			a.run()
		}
	}
	for _, rule := range []string{"secret:token-format", "secret:jwt", "secret:long-run", "secret:json-field", "secret:named-value", "secret:flag-value",
		"secret:header", "secret:scheme-value", "secret:colon-value"} {
		add(rule, found[rule])
	}
	return hits
}

// hasJWT: the audit's own JWT reading, not the scrubber's pattern: `eyJ` and three dot-joined base64url
// segments of at least 5 characters each after a word's start, of at least 10 glued to a word before it.
func hasJWT(s string) bool {
	for i := strings.Index(s, "eyJ"); i >= 0; {
		min := 5
		if i > 0 && (lex.IsAlnumASCII(s[i-1]) || s[i-1] == '_') {
			min = 10
		}
		j, segs := i, 0
		for segs < 3 {
			k := j
			for k < len(s) && (lex.IsAlnumASCII(s[k]) || s[k] == '-' || s[k] == '_') {
				k++
			}
			// The first segment's `eyJ` does not count toward its length, as the scrubber's patterns read it.
			need := min
			if segs == 0 {
				need += 3
			}
			if k-j < need {
				if segs == 0 {
					j = k
				}
				break
			}
			segs++
			if segs < 3 {
				if k >= len(s) || s[k] != '.' {
					break
				}
				k++
			}
			j = k
		}
		if segs == 3 && !lex.OnlyPlaceholders(s[i:j]) {
			return true
		}
		// On past the run just read, so a long run of `eyJ` is read once, not once per `eyJ`.
		from := i + 3
		if j > from {
			from = j
		}
		if from >= len(s) {
			break
		}
		n := strings.Index(s[from:], "eyJ")
		if n < 0 {
			break
		}
		i = from + n
	}
	return false
}

// receiverValueEnd: `"(?:\\.|[^"\\\n])*"?`, `'[^'\n]*'?` or `[^\s"']+` at i.
func receiverValueEnd(s string, i int) int {
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '"':
		return lex.DqEndLine(s, i)
	case '\'':
		le := lex.LineEnd(s, i+1)
		if k := strings.IndexByte(s[i+1:le], '\''); k >= 0 {
			return i + 1 + k + 1
		}
		return le
	}
	j := i
	for j < len(s) && !lex.IsSpaceByte(s[j]) && s[j] != '"' && s[j] != '\'' {
		j++
	}
	return j
}

// looksSecretOrFirstWord: the value, or its first word, looks random (a value read on past a
// quote written another way can hold words after the secret).
func looksSecretOrFirstWord(v string) bool {
	if vocab.LooksSecret(v) {
		return true
	}
	f := strings.Fields(strings.Trim(v, "\"'"))
	return len(f) > 0 && vocab.LooksSecret(f[0])
}

func anyOf(texts []string, f func(string) bool) bool {
	for _, t := range texts {
		if f(t) {
			return true
		}
	}
	return false
}

// hasPhone: a phone shape in any text the phone rule reads (phoneReadings).
func hasPhone(text string) bool {
	for _, r := range reading.PhoneReadings(text) {
		if detect.HasPhoneShape(r.Text) {
			return true
		}
	}
	return false
}
