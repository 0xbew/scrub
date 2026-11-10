package detect

import (
	"regexp"
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// --- the keyword precondition -----------------------------------------------------------

// keywordRx: a name run holding one of these is a candidate a random-looking value is judged
// under. A credential's name always holds one.
var keywordRx = regexp.MustCompile(`(?i)(?:key|token|secret|pass|passwd|password|pwd|dsn|credentials?|auth|pin|otp|mfa|2fa|(?:` +
	strings.Join(vocab.CodeOwners, "|") + `)[_-]?code)`)

var patRx = regexp.MustCompile(`(?i)pat`)

func HasKeyword(name string) bool {
	if keywordRx.MatchString(name) {
		return true
	}
	for _, m := range patRx.FindAllStringIndex(name, -1) {
		if m[1] >= len(name) || !(lex.IsLowerASCII(name[m[1]]) || lex.IsUpperASCII(name[m[1]])) {
			return true
		}
	}
	return false
}

// judged: whether a name's value is hidden: a credential's always; any other candidate's
// when the value, or its first word, looks random.
func judged(name, value string) bool {
	if vocab.IsCredentialName(name) {
		return true
	}
	if !HasKeyword(name) {
		return false
	}
	if vocab.LooksSecret(value) {
		return true
	}
	if f := strings.Fields(value); len(f) > 0 && vocab.LooksSecret(f[0]) {
		return true
	}
	return false
}
