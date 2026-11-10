package engine

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0xbew/scrub/internal/audit"
	"github.com/0xbew/scrub/internal/denylist"
	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
	"github.com/0xbew/scrub/internal/vocab"
)

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
				if !lex.OnlyPlaceholders(strings.Trim(last, "\"'`")) || !awaitsValue(rest[pw+1:]) {
					break
				}
			}
			kept = strings.TrimRightFunc(kept[:w], unicode.IsSpace)
		}
		// Nor where the audit reads the marker as a value left (a name in another form, `＝ …[cut]`, or a
		// closed value read on into the marker): words go from the end until it passes.
		// Only what the marker itself causes: a hit already in the kept text is not the cut's to answer.
		baseHit := secretHit(kept)
		baseMore := len(reread(kept, false, redetectSecrets).Spans) > 0
		for (!baseHit && secretHit(kept+" "+Cut)) || (!baseMore && len(reread(kept+" "+Cut, false, redetectSecrets).Spans) > 0) {
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
func redetectSecrets(t string) *span.Set { return detectText(t, denylist.None, modeRedact) }

// secretHit: the audit reads a secret's value in s (its secret rules; names and shapes are not the cut's).
func secretHit(s string) bool {
	for _, h := range audit.Audit(s, denylist.None) {
		if strings.HasPrefix(h, "secret:") {
			return true
		}
	}
	return false
}

// reshape: addresses and phone numbers again, on what was rendered: a name removed from
// beside a number can leave a phone shape that was not one before.
func reshape(out string) string {
	sp := &span.Set{}
	c := &detect.Scan{S: out, R: reading.Raw(out), Out: sp}
	c.Shapes()
	if len(sp.Spans) == 0 {
		return out
	}
	r, _ := render(out, sp, true)
	return r
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
	if w == "-H" || w == "--header" || lex.AuthSchemes[strings.ToLower(w)] {
		return true
	}
	// SQL's `IDENTIFIED BY x` and `PASSWORD x`: a receiver reads the marker as the value.
	if strings.EqualFold(w, "by") || strings.EqualFold(w, "password") {
		return true
	}
	// A name and its hidden value glued (`Authorization:<redacted>`): the marker reads as more of that value.
	if k := strings.LastIndexByte(w, ':'); k > 0 && k < len(w)-1 && lex.OnlyPlaceholders(w[k+1:]) {
		return true
	}
	if strings.HasPrefix(w, "-") {
		return vocab.IsCredentialName(strings.TrimLeft(w, "-")) || len(strings.TrimLeft(w, "-")) == 1
	}
	// A name glued to what was hidden before it (`"<redacted>"'<redacted>'-password`): the name is the word's tail.
	if k := strings.LastIndexAny(w, "\"'`>"); k >= 0 && k < len(w)-1 {
		return awaitsValue(w[k+1:])
	}
	return false
}
