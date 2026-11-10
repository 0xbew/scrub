package audit

import (
	"strings"

	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
	"github.com/0xbew/scrub/internal/vocab"
)

// headers: a credential's name as a header, quoted or bare, and a scheme then an assignment.
func (a *auditor) headers() {
	s := a.s
	for _, flag := range []string{"-H", "--header"} {
		for at := 0; ; {
			k := strings.Index(s[at:], flag)
			if k < 0 {
				break
			}
			f := at + k
			at = f + 1
			if f > 0 && (lex.WordBefore(s, f) || s[f-1] == '-') {
				continue
			}
			j := f + len(flag)
			if j < len(s) && s[j] == '=' {
				j++
			} else if e := lex.SkipBlanks(s, j); e > j {
				j = e
			} else {
				continue
			}
			var quote byte
			if j < len(s) && (s[j] == '"' || s[j] == '\'') {
				quote = s[j]
				j++
			}
			j = lex.SkipBlanks(s, j)
			for j < len(s) && s[j] == '-' {
				j++
			}
			ne := lex.NameRunAfter(s, j)
			if ne == j || !vocab.IsCredentialName(s[j:ne]) {
				continue
			}
			c := lex.SkipBlanks(s, ne)
			if c >= len(s) || s[c] != ':' {
				continue
			}
			v := lex.SkipBlanks(s, c+1)
			var val string
			var vlo, vhi int
			if quote != 0 {
				// Closed, the value runs to its own closing quote (inside double quotes an escaped one is
				// the value's); with no closing quote on the line, to the next quote of either kind or
				// backslash, as a receiver splitting the argument reads it.
				e := v
				closed := false
				for e < len(s) && s[e] != '\n' {
					if quote == '"' && s[e] == '\\' && e+1 < len(s) {
						e += 2
						continue
					}
					if s[e] == quote {
						closed = true
						break
					}
					e++
				}
				if e > len(s) {
					e = len(s)
				}
				if !closed {
					e = v
					if v < len(s) && (s[v] == '"' || s[v] == '\'') {
						// A value that opens the other quote is that quoted part (a truncated
						// `-H 'X-Api-Key:"V"`).
						_, e = lex.CrudeValue(s, v)
					} else {
						for e < len(s) && s[e] != '"' && s[e] != '\'' && s[e] != '\\' && s[e] != '\n' {
							e++
						}
					}
				}
				val = s[v:e]
				vlo, vhi = v, e
			} else {
				lo, hi := schemeValue(s, v)
				val = s[lo:hi]
				vlo, vhi = lo, hi
				// Unquoted, the receiver's value runs to a blank: a placeholder with anything glued to it
				// (`X-Token:<redacted>,`) is a value partly sent.
				if strings.HasPrefix(val, "<redacted") && val != lex.PhRedacted && !lex.OnlyPlaceholders(val) {
					a.hitAt("secret:header", vlo, vhi)
				}
			}
			if live(val) {
				a.hitAt("secret:header", vlo, vhi)
			}
		}
	}
	low := lex.AsciiLower(s)
	for _, w := range auditSchemeWords {
		{
			for at := 0; ; {
				k := strings.Index(low[at:], w)
				if k < 0 {
					break
				}
				b := at + k
				at = b + 1
				if b > 0 && (lex.IsLowerASCII(s[b-1]) || lex.IsUpperASCII(s[b-1])) {
					continue
				}
				j := b + len(w)
				n := lex.SkipBlanks(s, j)
				if n == j {
					continue
				}
				for n < len(s) && s[n] == '-' {
					n++
				}
				ne := lex.NameRunAfter(s, n)
				if ne == n || ne >= len(s) || (s[ne] != '=' && s[ne] != ':') || !vocab.IsCredentialName(s[n:ne]) {
					continue
				}
				lo, hi := schemeValue(s, ne+1)
				if live(s[lo:hi]) {
					a.hitAt("secret:scheme-value", lo, hi)
				}
			}
		}
	}
}

func isFixedHeader(name string) bool {
	low := strings.ToLower(name)
	for _, h := range detect.FixedHeaders {
		if low == h {
			return true
		}
	}
	return false
}

// LocateLive: the source spans of values the audit reads as sent that hold a placeholder: a
// value partly hidden. The scrubber hides them whole when it re-reads its own rendering, so
// its output passes its own audit.
func LocateLive(text string) *span.Set {
	out := &span.Set{}
	found := map[string]bool{}
	for _, r := range reading.Of(reading.Raw(text), true) {
		sp := &span.Set{}
		a := &auditor{r: r, s: r.Text, pct: r.Pct, found: found, spans: sp}
		a.run()
		for _, x := range sp.Spans {
			if hasPlaceholder(text[x.Lo:x.Hi]) {
				out.Add(x.Lo, x.Hi, span.KindSecret)
			}
		}
	}
	return out
}

func hasPlaceholder(v string) bool {
	for i := 0; i < len(v); i++ {
		if lex.PlaceholderAt(v, i) > 0 {
			return true
		}
	}
	return false
}

// auditSchemeWords: the words a scheme-written assignment follows (`Token password:x`), as the
// scrubber's schemeAssigned reads them.
var auditSchemeWords = []string{"bearer", "basic", "token", "digest", "negotiate", "ntlm", "apikey", "api-key"}
