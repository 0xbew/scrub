package auditnet

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// --- long random runs ---------------------------------------------------------------------------------------

const (
	netMinRun = 32
	// A random run switches between lower case, upper case and digits at about every other character; words
	// written as code (`CredentialProviderFactory2024`) switch once a word.
	netMinSwitchRate = 0.3
)

func netRunChar(c byte) bool { return lex.IsAlnumASCII(c) || c == '+' || c == '/' }

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
	case lex.IsLowerASCII(c):
		return 1
	case lex.IsUpperASCII(c):
		return 2
	case lex.IsDigitASCII(c):
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

func netJWTChar(c byte) bool { return lex.IsAlnumASCII(c) || c == '-' || c == '_' || c == '.' }

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
			if lex.IsAlnumASCII(w[j]) {
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
