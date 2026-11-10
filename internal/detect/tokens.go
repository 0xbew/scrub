package detect

import (
	"regexp"
	"strings"

	"github.com/0xbew/scrub/internal/gate"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
	"github.com/0xbew/scrub/internal/tokens"
	"github.com/0xbew/scrub/internal/vocab"
)

// --- tokens, JWTs and long random runs (R6, R7) ------------------------------------------

func (c *Scan) tokens() {
	tokens.TokenSpans(c.S, func(lo, hi int) { c.hideValue(lo, hi) })
}

var jwtRx = regexp.MustCompile(`\beyJ(?:(?:\\\r?\n)*[A-Za-z0-9_\-]){5,}(?:\\\r?\n)*\.(?:(?:\\\r?\n)*[A-Za-z0-9_\-]){5,}(?:\\\r?\n)*\.(?:(?:\\\r?\n)*[A-Za-z0-9_\-]){5,}`)

// jwtGluedRx: a JWT glued to a word before it, where `\b` cannot stand; longer segments, so a word that happens
// to hold `eyJ` and two dots is not read as one.
var jwtGluedRx = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)

func (c *Scan) jwt() {
	for _, m := range jwtRx.FindAllStringIndex(c.S, -1) {
		c.Hide(m[0], m[1], span.KindJWT)
	}
	for _, m := range jwtGluedRx.FindAllStringIndex(c.S, -1) {
		c.Hide(m[0], m[1], span.KindJWT)
	}
}

func isRunChar(ch byte) bool { return lex.IsAlnumASCII(ch) || ch == '_' || ch == '+' || ch == '/' }

// longRuns: any run of 32 or more token characters holding a letter and a digit, joined
// across continuations; kept when it is a path or an identifier written as code.
func (c *Scan) longRuns() {
	if gate.Off(gate.Long) {
		return
	}
	s := c.S
	i := 0
	for i < len(s) {
		if !isRunChar(s[i]) {
			i++
			continue
		}
		start := i
		count := 0
		j := i
		var plain strings.Builder
		for j < len(s) {
			if isRunChar(s[j]) {
				plain.WriteByte(s[j])
				count++
				j++
				continue
			}
			if n := lex.ContAt(s, j); n > 0 {
				k := SkipConts(s, j)
				if k < len(s) && isRunChar(s[k]) {
					j = k
					continue
				}
			}
			break
		}
		end := j
		eq := 0
		for end < len(s) && s[end] == '=' && eq < 2 {
			end++
			eq++
		}
		i = j
		if count < 32 {
			continue
		}
		body := plain.String()
		if !hasDigitAndAlphaASCII(body) {
			continue
		}
		token := s[start:end]
		if vocab.IsIdentifier(token) && vocab.WrittenAsCode(s, start, end) {
			continue
		}
		after := byte(0)
		if end < len(s) {
			after = s[end]
		}
		trim := strings.Trim(body, "/")
		if eq == 0 && (after == '.' || after == '-') && strings.Contains(trim, "/") && !strings.Contains(body, "+") &&
			!strings.Contains(token, "\\") && vocab.Wordlike(body, vocab.IsPathSep) {
			continue
		}
		c.Hide(start, end, span.KindLong)
	}
}

// HasLongRun: the long-run rule fires somewhere in a reading (the audit's check; it shares
// the classifier, so a value the scrubber keeps as a path or as code passes).
func HasLongRun(r *reading.Reading) bool {
	sp := &span.Set{}
	c := &Scan{S: r.Text, R: r, Out: sp}
	c.longRuns()
	for _, x := range sp.Spans {
		if !lex.OnlyPlaceholders(r.Src[x.Lo:x.Hi]) {
			return true
		}
	}
	return false
}

func hasDigitAndAlphaASCII(s string) bool {
	d, a := false, false
	for i := 0; i < len(s); i++ {
		if lex.IsDigitASCII(s[i]) {
			d = true
		} else if lex.IsLowerASCII(s[i]) || lex.IsUpperASCII(s[i]) {
			a = true
		}
	}
	return d && a
}
