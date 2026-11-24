// Package tokens finds secrets by their format: vendor tokens and password hashes.
package tokens

import (
	"slices"
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// Password hashes whose format says what they are, with no name before them: a crypt hash (`$2b$12$…`,
// `$argon2id$v=19$…`, Django's `pbkdf2_sha256$600000$…`) whose last field reads random (a digit, or both cases), and
// a scheme tag LDAP or Dovecot writes (`{SSHA}…`, `{PLAIN}pw`) with its value. The earlier Python scrubber's
// BARE_HASH reads the same shapes.

const (
	maxHashID      = 32  // a crypt id (`argon2id`) or Django's algorithm before it
	maxHashField   = 200 // one `$`-separated field before the last
	maxHashFields  = 6
	minHashLast    = 8
	minTaggedValue = 2  // after a plain password's tag: a password may be short (`{PLAIN}pw`)
	minTaggedHash  = 12 // after a digest's or a crypt hash's: `{SHA}-linux` is a template's
	maxSchemeName  = 13 // GOST_YESCRYPT
)

var hashSchemes = func() map[string]bool {
	m := map[string]bool{}
	for n := range strings.FieldsSeq(`SSHA SSHA1 SSHA224 SSHA256 SSHA384 SSHA512 SHA SHA1 SHA224 SHA256 SHA384 SHA512 SMD5
		MD5 CRYPT BCRYPT PLAIN-MD4 PLAIN-MD5 BLF-CRYPT SHA256-CRYPT SHA512-CRYPT MD5-CRYPT
		DES-CRYPT YESCRYPT GOST_YESCRYPT CRAM-MD5 DIGEST-MD5 LDAP-MD5 ARGON2I ARGON2ID X-PBKDF2 PBKDF2 PBKDF2-SHA1
		PBKDF2-SHA256 PBKDF2-SHA512 PBKDF2_SHA256 PBKDF2_SHA512 SCRAM-SHA-1 SCRAM-SHA-256 NTLM LANMAN K5KEY SASL`) {
		m[n] = true
	}
	return m
}()

var plainSchemes = map[string]bool{"PLAIN": true, "PLAIN-TRUNC": true, "CLEAR": true, "CLEARTEXT": true}

func isHashChar(c byte) bool { return lex.IsAlnumASCII(c) || strings.IndexByte("_./+=-", c) >= 0 }

func isHashIDChar(c byte) bool { return lex.IsAlnumASCII(c) || c == '_' || c == '-' }

// hashSpans emits each password hash in s, read once from its start.
func hashSpans(s string, emit func(lo, hi int)) {
	for i := 0; i < len(s); i++ {
		lo, hi := -1, -1
		switch s[i] {
		case '$':
			lo, hi = cryptHashAt(s, i)
		case '{':
			lo, hi = i, taggedHashEnd(s, i)
		}
		if hi > 0 {
			emit(lo, hi)
			i = hi - 1
		}
	}
}

// cryptHashAt: the crypt hash whose head's `$` is at i (`$id$`, perhaps after Django's algorithm word), then one to
// maxHashFields fields each ended by a `$`, then a last field of minHashLast hash characters that reads random. The
// last field is the latest one that qualifies. Returns its span, or -1, -1.
func cryptHashAt(s string, i int) (int, int) {
	lo := hashStart(s, i)
	if lo < 0 {
		return -1, -1
	}
	starts := fieldStarts(s, cryptIDEnd(s, i))
	for _, p := range slices.Backward(starts) {
		if e := randomLastEnd(s, p); e > 0 {
			return lo, e
		}
	}
	return -1, -1
}

// hashStart: where a crypt hash whose head's `$` is at i starts: there, or at Django's algorithm word glued before
// it (`pbkdf2_sha256$…`); -1 when a hash character other than `=` (`hash=$2b$…`), or a `$`, stands before it.
func hashStart(s string, i int) int {
	lo := i
	for lo > 0 && isHashIDChar(s[lo-1]) {
		lo--
	}
	if lo < i && (i-lo > maxHashID || !lex.IsUpperASCII(s[lo]) && !lex.IsLowerASCII(s[lo])) {
		return -1
	}
	if lo > 0 && (isHashChar(s[lo-1]) && s[lo-1] != '=' || s[lo-1] == '$') {
		return -1
	}
	return lo
}

// cryptIDEnd: just past the `$` that closes the crypt id after the `$` at i (`$2b$`), or -1.
func cryptIDEnd(s string, i int) int {
	j := i + 1
	if j >= len(s) || !lex.IsAlnumASCII(s[j]) {
		return -1
	}
	for j < len(s) && isHashIDChar(s[j]) {
		j++
	}
	if j-i-1 > maxHashID || j >= len(s) || s[j] != '$' {
		return -1
	}
	return j + 1
}

// fieldStarts: from p (-1: none), where each field after one to maxHashFields fields ended by a `$` starts.
func fieldStarts(s string, p int) []int {
	if p < 0 {
		return nil
	}
	starts := make([]int, 0, maxHashFields)
	for len(starts) < maxHashFields {
		k := p
		for k < len(s) && k-p <= maxHashField && !lex.IsSpaceByte(s[k]) && strings.IndexByte("$\"'`\\", s[k]) < 0 {
			k++
		}
		if k == p || k-p > maxHashField || k >= len(s) || s[k] != '$' {
			break
		}
		p = k + 1
		starts = append(starts, p)
	}
	return starts
}

// randomLastEnd: the end of the run of hash characters at p when it is minHashLast long and holds a digit or both
// cases, else -1.
func randomLastEnd(s string, p int) int {
	e := p
	digit, lower, upper := false, false, false
	for e < len(s) && isHashChar(s[e]) {
		digit = digit || lex.IsDigitASCII(s[e])
		lower = lower || lex.IsLowerASCII(s[e])
		upper = upper || lex.IsUpperASCII(s[e])
		e++
	}
	if e-p < minHashLast || !digit && (!lower || !upper) {
		return -1
	}
	return e
}

// taggedHashEnd: the end of a known scheme tag at i, in capitals as LDAP and Dovecot write it (`{SSHA}`; `{sha}` is a
// template's), and the value glued to it: minTaggedHash characters or more (minTaggedValue after a plain password's
// tag) to a blank, a quote or a backslash, not
// a placeholder (`{SSHA}<redacted>`); -1 otherwise. A plain password takes any punctuation
// but the `,;)]}` that end it (`{password:{SSHA}…}`).
func taggedHashEnd(s string, i int) int {
	if i > 0 && (lex.IsAlnumASCII(s[i-1]) || s[i-1] == '_' || s[i-1] == '$') {
		return -1
	}
	end := strings.IndexByte(s[i+1:min(len(s), i+2+maxSchemeName)], '}')
	if end < 0 {
		return -1
	}
	minValue := minTaggedHash
	switch name := s[i+1 : i+1+end]; {
	case plainSchemes[name]:
		minValue = minTaggedValue
	case !hashSchemes[name]:
		return -1
	}
	v := i + 2 + end
	if strings.HasPrefix(s[v:], "<redacted>") || strings.HasPrefix(s[v:], "<long-token>") {
		return -1
	}
	e := v
	for e < len(s) && !lex.IsSpaceByte(s[e]) && strings.IndexByte("\"'`\\", s[e]) < 0 {
		e++
	}
	for e > v && strings.IndexByte(",;)]}", s[e-1]) >= 0 {
		e--
	}
	if e-v < minValue {
		return -1
	}
	return e
}
