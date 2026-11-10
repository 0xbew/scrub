package auditnet

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// --- cookies, program options and colon values --------------------------------------------------------------

// netCookie: a Cookie or Set-Cookie header holding a pair (`name=value`) whose value is not a placeholder.
func netCookie(s string) bool {
	lowered := lex.AsciiLower(s)
	for k := strings.Index(lowered, "cookie:"); k >= 0; {
		if k == 0 || !lex.IsAlnumASCII(s[k-1]) || strings.HasSuffix(lowered[:k], "set-") {
			end := lex.LineEnd(s, k)
			if q := netQuoteBefore(s, k); q != 0 {
				if e := strings.IndexByte(s[k:end], q); e >= 0 {
					end = k + e
				}
			}
			if netPairLive(s[k+len("cookie:") : end]) {
				return true
			}
			k = end - 1 // a later header on the line was read as part of this one's pairs
		}
		next := strings.Index(lowered[k+1:], "cookie:")
		if next < 0 {
			break
		}
		k += 1 + next
	}
	return false
}

// netQuoteBefore: the quote that opens the header's word (`-H "Cookie: …"`), if any.
func netQuoteBefore(s string, k int) byte {
	for i := k - 1; i >= 0 && s[i] != '\n'; i-- {
		switch s[i] {
		case '"', '\'':
			return s[i]
		case ' ', '\t':
			return 0
		}
	}
	return 0
}

// netPairLive: the header's `name=value` pairs, each closed by `;` but the last, one of them with a value that is
// not placeholders; the first word that is no pair ends the header (the line's text after it is not the cookie's).
func netPairLive(v string) bool {
	for i := 0; i < len(v); {
		for i < len(v) && (v[i] == ' ' || v[i] == '\t') {
			i++
		}
		eq := i
		for eq < len(v) && v[eq] != '=' && v[eq] != ';' && !lex.IsSpaceByte(v[eq]) {
			eq++
		}
		if eq == i || eq >= len(v) || v[eq] != '=' {
			return false
		}
		e := eq + 1
		for e < len(v) && v[e] != ';' && !lex.IsSpaceByte(v[e]) {
			e++
		}
		if val := v[eq+1 : e]; val != "" && !lex.OnlyPlaceholders(val) {
			return true
		}
		if e >= len(v) || v[e] != ';' {
			return false
		}
		i = e + 1
	}
	return false
}

// netPrograms: a program whose short option holds a password, and whether the value may also stand apart.
var netPrograms = []struct {
	name, option string
	apart        bool
}{
	{"mysql", "-p", false}, {"mysqldump", "-p", false}, {"mysqladmin", "-p", false}, {"mysqlimport", "-p", false},
	{"mysqlcheck", "-p", false}, {"mysqlshow", "-p", false}, {"mariadb", "-p", false}, {"mariadb-dump", "-p", false},
	{"sshpass", "-p", true}, {"redis-cli", "-a", true},
}

// netProgramOption: one of netPrograms, then on its command (to `;`, `|`, `&` or the line's end) its option with
// a value glued to it (or after a blank, where the program allows it) that is not a placeholder.
func netProgramOption(s string) bool {
	for _, p := range netPrograms {
		for k := strings.Index(s, p.name); k >= 0; {
			after := k + len(p.name)
			if (k == 0 || !netProgChar(s[k-1])) && (after >= len(s) || !netProgChar(s[after])) {
				end := after
				for end < len(s) && strings.IndexByte(";|&\n", s[end]) < 0 {
					end++
				}
				if netOptionLive(s[after:end], p.option, p.apart) {
					return true
				}
				k = end - 1 // the program again on the same command: its options were just read
			}
			next := strings.Index(s[k+1:], p.name)
			if next < 0 {
				break
			}
			k += 1 + next
		}
	}
	return false
}

func netProgChar(c byte) bool { return lex.IsAlnumASCII(c) || c == '-' || c == '_' || c == '.' }

func netOptionLive(cmd, option string, apart bool) bool {
	f := strings.Fields(cmd)
	for i := 0; i < len(f); i++ {
		w := strings.Trim(f[i], "\"'")
		if !strings.HasPrefix(w, "-") {
			// The program's first plain argument (a database, a host command) ends its own options: what follows
			// on the line is another program's or prose (`find . -print`).
			return false
		}
		if w == option {
			if apart && i+1 < len(f) && netOptionValue(strings.Trim(f[i+1], "\"'")) {
				return true
			}
		} else if strings.HasPrefix(w, option) && !strings.HasPrefix(w, "--") {
			if netOptionValue(strings.Trim(w[len(option):], "\"'")) {
				return true
			}
			continue
		}
		// An option that takes its value apart (`-u app`, `--port 3306`) skips it.
		if (len(w) == 2 || strings.HasPrefix(w, "--") && !strings.Contains(w, "=")) && i+1 < len(f) && !strings.HasPrefix(f[i+1], "-") {
			i++
		}
	}
	return false
}

// netOptionValue: an option's value that is not another option, a reference (`$PW`, `%s`, `{pw}`), placeholders, or
// prose and markup around a program's name (“ `openssl “, `(see`), or a written escape (`\n`).
func netOptionValue(v string) bool {
	return v != "" && strings.IndexByte("-$%{<`()[],;\\", v[0]) < 0 && !lex.OnlyPlaceholders(v)
}

// netNamedValue: a credential's name standing as a word, then `:` and a blank (or a quoted name and `:`), or a
// blank, `=` and a blank, then one word that reads as a value: letters and digits mixed, or letters only and long.
// Letters only count from eight letters after a name whose last word is the credential itself (`password`,
// `DB_PASSWORD`, `api_key`), at a YAML line's start for any name, and from thirteen otherwise.
func netNamedValue(s string) bool {
	// The line's last `{` and `}` so far: a name after an unclosed `{` stands in a flow mapping.
	lastOpen, lastClose := -1, -1
	for p := 0; p < len(s); p++ {
		c := s[p]
		switch c {
		case '\n':
			lastOpen, lastClose = -1, -1
		case '{':
			lastOpen = p
		case '}':
			lastClose = p
		}
		if c != ':' && c != '=' {
			continue
		}
		q := p
		if c == '=' {
			if p+1 < len(s) && (s[p+1] == '=' || s[p+1] == '~') {
				continue
			}
			for q > 0 && (s[q-1] == ' ' || s[q-1] == '\t') {
				q--
			}
			if q == p || p+1 >= len(s) || (s[p+1] != ' ' && s[p+1] != '\t') {
				continue // `NAME=value` is the assignment check's
			}
		}
		quoted := c == ':' && q > 0 && (s[q-1] == '"' || s[q-1] == '\'')
		if quoted {
			q--
		}
		n := q
		for n > 0 && (lex.IsAlnumASCII(s[n-1]) || s[n-1] == '_' || s[n-1] == '-') {
			n--
		}
		if n == q {
			continue
		}
		name := s[n:q]
		if quoted {
			if n == 0 || s[n-1] != s[q] {
				continue
			}
			n--
		}
		if n > 0 && (lex.IsAlnumASCII(s[n-1]) || strings.IndexByte(".$@#/\\", s[n-1]) >= 0) {
			continue // a member, a variable or a path: not a name standing as a word
		}
		if !vocab.IsCredentialName(name) {
			continue
		}
		v := p + 1
		for v < len(s) && (s[v] == ' ' || s[v] == '\t') {
			v++
		}
		if c == ':' && v == p+1 && !quoted {
			continue // `name:value` with no blank is a URL's scheme or a time as often as a value
		}
		yaml := c == ':' && netLineHead(s, n)
		flow := c == ':' && lastOpen > lastClose
		e := v
		for e < len(s) && e-v < netMaxWord && !lex.IsSpaceByte(s[e]) && !(flow && (s[e] == ',' || s[e] == '}')) {
			e++
		}
		// A JSON key's value is a string; unquoted it is a number, a literal or no JSON at all.
		if quoted && (v >= len(s) || s[v] != '"' && s[v] != '\'' && s[v] != '\\') {
			continue
		}
		if netValueWord(s[v:e], netStrongName(name) || yaml) {
			return true
		}
	}
	return false
}

var netStrongKeyOwners = lex.SetOf("api", "secret", "private", "access")

// netMaxWord bounds the word read after a name, so a long line of names glued to values stays linear.
const netMaxWord = 256

// netStrongName: a name whose last word is the credential itself.
func netStrongName(name string) bool {
	words := vocab.NameWords(name)
	if len(words) == 0 {
		return false
	}
	last := strings.ToLower(words[len(words)-1])
	if last == "key" {
		return len(words) > 1 && netStrongKeyOwners[strings.ToLower(words[len(words)-2])]
	}
	for _, e := range []string{"password", "passwd", "passphrase", "pwd", "secret", "token", "apikey"} {
		if strings.HasSuffix(last, e) {
			return true
		}
	}
	return false
}

// netLineHead: a name first on its line after blanks, an opening quote, a diff row's marker or a YAML list's `- `,
// or after a flow mapping's `{` or `,`.
func netLineHead(s string, n int) bool {
	i := n
	for i > 0 && strings.IndexByte(" \t\"'\\", s[i-1]) >= 0 {
		i--
	}
	if i > 0 && (s[i-1] == '{' || s[i-1] == ',') {
		return true
	}
	if i > 0 && s[i-1] == '-' {
		i--
		for i > 0 && strings.IndexByte(" \t\"'\\", s[i-1]) >= 0 {
			i--
		}
	}
	if i > 0 && (s[i-1] == '+' || s[i-1] == '-') && (i == 1 || s[i-2] == '\n') {
		i--
	}
	return i == 0 || s[i-1] == '\n'
}

// netProse: words a YAML or a sentence puts after a credential's name that hold no value.
var netProse = lex.SetOf("required", "optional", "undefined", "changeme", "redacted", "placeholder", "password",
	"passwords", "secret", "secrets", "token", "tokens", "example", "missing", "invalid", "expired", "disabled",
	"enabled", "string", "boolean", "integer", "nullable", "default", "unknown", "rotated", "provided", "supplied",
	"generated", "configured", "available", "required", "returned", "omitted")

// netValueWord: the word after a name, its wrapping and closing punctuation aside, reads as a value: not a
// placeholder, a reference or code, and either letters mixed with digits, or letters only and long.
func netValueWord(w string, strong bool) bool {
	for _, open := range []string{"**", "\\\"", "\"", "'", "`", "(", "["} {
		w = strings.TrimPrefix(w, open)
	}
	w = strings.TrimRight(w, ".,;:!?)]}>*`\"'\\")
	if w == "" || lex.OnlyPlaceholders(w) || strings.ContainsAny(w[:1], "$%{|>&*!~<[") || netProse[strings.ToLower(w)] {
		return false
	}
	letters, digits, upper, seps := 0, 0, 0, 0
	for i := 0; i < len(w); i++ {
		switch ch := w[i]; {
		case lex.IsDigitASCII(ch):
			digits++
		case lex.IsLowerASCII(ch):
			letters++
		case lex.IsUpperASCII(ch):
			letters++
			if i > 0 {
				upper++
			}
		case ch == '-' || ch == '_' || ch == '+' || ch == '/' || ch == '=' || ch == '.' || ch == '~':
			seps++
		default:
			return false // a call, a type or markup: code, not a value
		}
	}
	switch {
	case digits > 0 && letters > 0:
		return letters+digits >= 6
	case digits > 0 || seps > 0:
		return false // a count, or letters joined as an identifier (`secret_scope`, `self.token`)
	case lex.IsUpperASCII(w[0]):
		return false // a type or a name (`secret: SecretStr`, `token: Optional`)
	case strong:
		return letters >= 8
	}
	// Letters only, after any name: long, and lower case throughout or capitals at random, not a type's humps.
	return letters >= 13 && (upper == 0 || upper*4 >= letters)
}
