package vocab

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
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

var codeOwners = lex.SetOf(CodeOwners...)

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
var quantityWords = lex.SetOf("max", "min", "num", "total", "input", "output", "prompt", "completion", "cache", "reasoning",
	"avg", "mean", "estimated", "n", "cached", "new", "stop", "special")

var passWords = lex.SetOf("bypass", "compass", "surpass", "overpass", "underpass", "trespass", "encompass")

// KeyOwners: a word that owns a `key` (api_key, ssh_key).
var KeyOwners = []string{"api", "access", "secret", "private", "signing", "sign", "encryption", "client", "app", "master",
	"license", "service", "auth", "ssh", "deploy", "hmac", "webhook", "session", "publishable", "admin", "account",
	"consumer", "subscription", "integration", "gpg", "pgp", "jwt", "root"}

var keyOwners = lex.SetOf(KeyOwners...)

// A last word that makes the name describe a credential rather than hold one: token_count, password_file.
var aboutACredential = lex.SetOf("id", "ids", "count", "counts", "type", "kind", "name", "names", "len", "length", "size",
	"limit", "max", "min", "url", "uri", "endpoint", "file", "path", "dir", "env", "var", "mode", "scheme", "expiry",
	"expires", "ttl", "budget", "usage", "version", "index", "enabled", "required")

var usageWords = lex.SetOf("used", "remaining", "left")

// NameWords splits a name the way `[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+` finds words: an
// acronym, a capitalised or lowercase word, a number. Anything else separates.
func NameWords(name string) []string {
	var out []string
	i, n := 0, len(name)
	for i < n {
		c := name[i]
		switch {
		case lex.IsUpperASCII(c):
			j := i
			for j < n && lex.IsUpperASCII(name[j]) {
				j++
			}
			if j < n && lex.IsLowerASCII(name[j]) {
				if j-i >= 2 {
					out = append(out, name[i:j-1])
					i = j - 1
				}
				// [A-Z]?[a-z]+
				k := i + 1
				for k < n && lex.IsLowerASCII(name[k]) {
					k++
				}
				out = append(out, name[i:k])
				i = k
				continue
			}
			out = append(out, name[i:j])
			i = j
		case lex.IsLowerASCII(c):
			j := i
			for j < n && lex.IsLowerASCII(name[j]) {
				j++
			}
			out = append(out, name[i:j])
			i = j
		case lex.IsDigitASCII(c):
			j := i
			for j < n && lex.IsDigitASCII(name[j]) {
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
	words := NameWords(name)
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
var strongKeyOwners = lex.SetOf("api", "secret", "private", "access")

// StrongCredentialName: a credential's name whose last word is the credential itself. After it mid-sentence a plain
// word is the value (`see password: letmein here`), where after a weaker name it is read as the sentence going on.
func StrongCredentialName(name string) bool {
	if !IsCredentialName(name) {
		return false
	}
	words := NameWords(name)
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
