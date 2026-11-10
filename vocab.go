package scrub

import (
	"regexp"
	"strings"
	"unicode"
)

// The credential-name vocabulary. A name is a credential's when one of its words says so;
// `key` and `pass` alone are ordinary words in code, so they count only in capitals, after a
// word that owns a key, or (pass) as the last word.

var singularWords = []string{"password", "passwd", "passphrase", "pwd", "secret", "secrets", "token", "credential",
	"credentials", "dsn", "pat", "auth", "authorization", "apikey", "privatekey", "accesskey", "secretkey", "passcode",
	"pincode", "otp", "totp", "hotp"}

// `pats` is not a name: `pat` is a GitHub token abbreviation, its plural an ordinary word.
var pluralExempt = map[string]bool{"pat": true}

var credentialWords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range singularWords {
		m[w] = true
		if !pluralExempt[w] {
			m[w+"s"] = true
		}
	}
	return m
}()

// CodeOwners: `code` holds a credential only after one of these (mfa_code, backup_code).
var CodeOwners = []string{"mfa", "2fa", "recovery", "backup", "verification", "security", "pin", "otp", "auth", "sms",
	"pass", "authentication", "oauth"}

var codeOwners = setOf(CodeOwners...)

var credentialEndings = func() []string {
	out := []string{"password", "passwd", "secret", "token", "apikey"}
	for _, o := range CodeOwners {
		out = append(out, strings.TrimLeft(o, "0123456789")+"code")
	}
	n := len(out)
	for _, e := range out[:n] {
		out = append(out, e+"s")
	}
	return out
}()

// `tokens` after a word that counts them is LLM tokens: max_tokens, prompt_tokens.
var quantityWords = setOf("max", "min", "num", "total", "input", "output", "prompt", "completion", "cache", "reasoning",
	"avg", "mean", "estimated", "n", "cached", "new", "stop", "special")

var passWords = setOf("bypass", "compass", "surpass", "overpass", "underpass", "trespass", "encompass")

// KeyOwners: a word that owns a `key` (api_key, ssh_key).
var KeyOwners = []string{"api", "access", "secret", "private", "signing", "sign", "encryption", "client", "app", "master",
	"license", "service", "auth", "ssh", "deploy", "hmac", "webhook", "session", "publishable", "admin", "account",
	"consumer", "subscription", "integration", "gpg", "pgp", "jwt", "root"}

var keyOwners = setOf(KeyOwners...)

// A last word that makes the name describe a credential rather than hold one: token_count, password_file.
var aboutACredential = setOf("id", "ids", "count", "counts", "type", "kind", "name", "names", "len", "length", "size",
	"limit", "max", "min", "url", "uri", "endpoint", "file", "path", "dir", "env", "var", "mode", "scheme", "expiry",
	"expires", "ttl", "budget", "usage", "version", "index", "enabled", "required")

var usageWords = setOf("used", "remaining", "left")

func setOf(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func isUpperASCII(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLowerASCII(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigitASCII(c byte) bool { return c >= '0' && c <= '9' }
func isAlnumASCII(c byte) bool { return isUpperASCII(c) || isLowerASCII(c) || isDigitASCII(c) }

// nameWords splits a name the way `[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+` finds words: an
// acronym, a capitalised or lowercase word, a number. Anything else separates.
func nameWords(name string) []string {
	var out []string
	i, n := 0, len(name)
	for i < n {
		c := name[i]
		switch {
		case isUpperASCII(c):
			j := i
			for j < n && isUpperASCII(name[j]) {
				j++
			}
			if j < n && isLowerASCII(name[j]) {
				if j-i >= 2 {
					out = append(out, name[i:j-1])
					i = j - 1
				}
				// [A-Z]?[a-z]+
				k := i + 1
				for k < n && isLowerASCII(name[k]) {
					k++
				}
				out = append(out, name[i:k])
				i = k
				continue
			}
			out = append(out, name[i:j])
			i = j
		case isLowerASCII(c):
			j := i
			for j < n && isLowerASCII(name[j]) {
				j++
			}
			out = append(out, name[i:j])
			i = j
		case isDigitASCII(c):
			j := i
			for j < n && isDigitASCII(name[j]) {
				j++
			}
			out = append(out, name[i:j])
			i = j
		default:
			i++
		}
	}
	return out
}

func hasAnySuffix(w string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(w, s) {
			return true
		}
	}
	return false
}

// IsCredentialName reports whether a NAME in `NAME=value`, `"name": value` or `name: value`
// holds a credential.
func IsCredentialName(name string) bool {
	words := nameWords(name)
	lowered := make([]string, len(words))
	for i, w := range words {
		lowered[i] = strings.ToLower(w)
	}
	if len(words) > 1 && aboutACredential[lowered[len(words)-1]] {
		return false
	}
	usage := len(words) > 1 && usageWords[lowered[len(words)-1]]
	for i, raw := range words {
		word := lowered[i]
		if (word == "code" || word == "codes") && i > 0 && codeOwners[lowered[i-1]] {
			return true
		}
		if word == "fa" && i > 0 && lowered[i-1] == "2" {
			return true
		}
		if word == "pin" && i == len(words)-1 {
			return true
		}
		counted := false
		if word == "tokens" {
			if i > 0 {
				counted = quantityWords[lowered[i-1]]
			} else {
				counted = usage
			}
		}
		if (credentialWords[word] || hasAnySuffix(word, credentialEndings)) && !counted {
			return true
		}
		if word == "key" || word == "keys" || word == "pass" {
			if strings.ToUpper(raw) == raw && strings.ToLower(raw) != raw {
				return true
			}
			if i > 0 && keyOwners[lowered[i-1]] {
				return true
			}
			if len(words) == 1 && word == "pass" {
				return true
			}
		}
		if word == "pass" && i == len(words)-1 {
			return true
		}
		if strings.HasSuffix(word, "pass") && !passWords[word] {
			return true
		}
	}
	return false
}

// strongEndings: a credential name's last word that holds nothing but the credential itself (`password`, `DB_PASSWORD`,
// `SLACK_BOT_TOKEN`, `client_secret`); `auth`, `dsn`, `pat` or `otp` may as well name a setting.
var strongEndings = []string{"password", "passwd", "passphrase", "pwd", "passcode", "secret", "token", "apikey",
	"secretkey", "privatekey", "accesskey"}

// strongKeyOwners: `key` after one of these is the credential itself (api_key, AWS_SECRET_ACCESS_KEY).
var strongKeyOwners = setOf("api", "secret", "private", "access")

// strongCredentialName: a credential's name whose last word is the credential itself. After it mid-sentence a plain
// word is the value (`see password: letmein here`), where after a weaker name it is read as the sentence going on.
func strongCredentialName(name string) bool {
	if !IsCredentialName(name) {
		return false
	}
	words := nameWords(name)
	if len(words) == 0 {
		return false
	}
	last := strings.ToLower(words[len(words)-1])
	// `PWD` alone, in capitals, is the shell's working directory; `pwd` is a password's label too.
	if name == "PWD" {
		return false
	}
	if last == "key" {
		return len(words) > 1 && strongKeyOwners[strings.ToLower(words[len(words)-2])]
	}
	return hasAnySuffix(last, strongEndings)
}

// --- the value classifier -------------------------------------------------------------

const (
	minSecretChars    = 16
	maxMixedPartChars = 20
)

var (
	wordPartRx  = regexp.MustCompile(`^(?:\d+|\d+(?:[a-z]+|[A-Z]+|[a-z]*(?:[A-Z][a-z]{2,})+)|(?:[a-z]+|[A-Z]+|[a-z]*(?:[A-Z][a-z]{2,})+)(?:\d+(?:[a-z]{3,}|[A-Z]{3,}|(?:[A-Z][a-z]{2,})+)?)?)$`)
	shortPartRx = regexp.MustCompile(`^(?:[a-z0-9]*|[A-Z0-9]+|[A-Z][a-z]+)$`)
)

func isValueSep(r rune) bool { return strings.ContainsRune("-_./:@+=,;()[]{}\\", r) }
func isPathSep(r rune) bool  { return r == '/' || r == '_' }

func splitRuns(text string, sep func(rune) bool) []string {
	// re.split keeps empty strings at the ends and between nothing; a run of separators is one split.
	var parts []string
	start := 0
	inSep := false
	for i, r := range text {
		if sep(r) {
			if !inSep {
				parts = append(parts, text[start:i])
				inSep = true
			}
		} else if inSep {
			start = i
			inSep = false
		}
	}
	if inSep {
		parts = append(parts, "")
	} else {
		parts = append(parts, text[start:])
	}
	return parts
}

func isAlphaStr(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func isDigitStr(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func runeLen(s string) int { return len([]rune(s)) }

func wordlike(text string, sep func(rune) bool) bool {
	for _, part := range splitRuns(text, sep) {
		if runeLen(part) <= 3 {
			if !shortPartRx.MatchString(part) {
				return false
			}
			continue
		}
		if !wordPartRx.MatchString(part) {
			return false
		}
		if runeLen(part) > maxMixedPartChars && !isAlphaStr(part) {
			return false
		}
	}
	return true
}

func hasDigitAndAlpha(s string) bool {
	d, a := false, false
	for _, r := range s {
		if unicode.IsDigit(r) {
			d = true
		} else if unicode.IsLetter(r) {
			a = true
		}
	}
	return d && a
}

// LooksSecret reports whether a value with no name to vouch for it is random-looking text
// of 16 or more characters.
func LooksSecret(value string) bool {
	value = strings.Trim(value, "\"'")
	if runeLen(value) < minSecretChars || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return false
	}
	if !hasDigitAndAlpha(value) {
		return false
	}
	return strings.IndexFunc(value, isValueSep) < 0 || !wordlike(value, isValueSep)
}

func keepUnlessSecret(name, value string) bool {
	return !IsCredentialName(name) && !LooksSecret(value)
}

// --- identifiers written as code --------------------------------------------------------

const (
	maxIdentWordChars     = 20
	maxIdentMixedChars    = 6
	maxIdentMixedParts    = 2
	maxIdentNumberChars   = 8
	maxIdentConsonantRun  = 4
	minIdentVowelShare    = 0.25
	minIdentLongestWord   = 5
	maxDefinitionIndent   = 64
	identifierMinRunChars = 32
)

var identMixedRx = regexp.MustCompile(`^(?:[a-z]+[0-9]+|[0-9]+[a-z]{1,4}|[a-z]{1,2}[0-9]{1,2}[a-z]{1,2})$`)

func isConsonant(c byte) bool {
	return isLowerASCII(c) && !strings.ContainsRune("aeiou", rune(c))
}

// IsIdentifier reports whether a long run is lowercase words joined by `_`
// (`test_a_401_stops_the_run_instead_of_marching_on`).
func IsIdentifier(run string) bool {
	if run == "" {
		return false
	}
	for i := 0; i < len(run); i++ {
		c := run[i]
		if !(isLowerASCII(c) || isDigitASCII(c) || c == '_') {
			return false
		}
	}
	var parts []string
	for _, p := range strings.Split(run, "_") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	trimmed := strings.TrimLeft(run, "_")
	if len(parts) == 0 {
		return false
	}
	for _, p := range identPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return false
		}
	}
	mixed := 0
	longest := false
	for _, part := range parts {
		var limit int
		switch {
		case isAlphaStr(part):
			limit = maxIdentWordChars
			if len(part) >= minIdentLongestWord {
				longest = true
			}
		case isDigitStr(part):
			limit = maxIdentNumberChars
		default:
			mixed++
			if identMixedRx.MatchString(part) {
				limit = maxIdentMixedChars
			}
		}
		if len(part) > limit {
			return false
		}
	}
	if mixed > maxIdentMixedParts || !longest {
		return false
	}
	runLen := 0
	letters, vowels := 0, 0
	for i := 0; i < len(run); i++ {
		c := run[i]
		// [b-df-hj-np-tv-xz]: y is neither a consonant here nor a break.
		if isLowerASCII(c) && c != 'y' && !strings.ContainsRune("aeiou", rune(c)) {
			runLen++
			if runLen > maxIdentConsonantRun {
				return false
			}
		} else {
			runLen = 0
		}
		if isLowerASCII(c) {
			letters++
			if strings.ContainsRune("aeiouy", rune(c)) {
				vowels++
			}
		}
	}
	return float64(vowels) >= minIdentVowelShare*float64(letters)
}

// writtenAsCode: a run that is a test's name, a call, a dotted path's part after its
// package, a `::` node id's name, or a definition's name.
func writtenAsCode(text string, start, end int) bool {
	if strings.HasPrefix(text[start:end], "test_") {
		return true
	}
	if end < len(text) && text[end] == '(' {
		return true
	}
	if start >= 2 {
		b := text[start-2 : start]
		if b == "::" || (b[1] == '.' && (isAlnumASCII(b[0]) || b[0] == '_')) {
			return true
		}
	}
	lo := start - maxDefinitionIndent
	if lo < 0 {
		lo = 0
	}
	line := strings.LastIndexByte(text[lo:start], '\n')
	if line >= 0 {
		line += lo + 1
	} else {
		line = 0
	}
	if line > 0 || start <= maxDefinitionIndent {
		return isDefinitionLead(text[line:start])
	}
	return false
}

// `[+ -]?[ \t]*(?:async[ \t]+)?(?:def|class)[ \t]+` as a whole.
func isDefinitionLead(s string) bool {
	if s != "" && (s[0] == '+' || s[0] == ' ' || s[0] == '-') {
		// The marker is optional; a leading space may also be indentation. Both readings.
		if isDefinitionBody(s[1:]) {
			return true
		}
	}
	return isDefinitionBody(s)
}

func isDefinitionBody(s string) bool {
	s = strings.TrimLeft(s, " \t")
	if strings.HasPrefix(s, "async") {
		rest := s[5:]
		if t := strings.TrimLeft(rest, " \t"); len(t) < len(rest) {
			s = t
		}
	}
	for _, kw := range []string{"def", "class"} {
		if strings.HasPrefix(s, kw) {
			rest := s[len(kw):]
			if rest != "" && strings.Trim(rest, " \t") == "" {
				return true
			}
		}
	}
	return false
}
