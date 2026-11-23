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

// netBearerWord: an Authorization header's Bearer scheme, then one word that reads as a value after a strong name
// (netValueWord): letters mixed with digits from six, or letters only from eight, which no other check reads.
func netBearerWord(s string) bool {
	lowered := lex.AsciiLower(s)
	for k := strings.Index(lowered, "authorization"); k >= 0; {
		if k == 0 || !lex.IsAlnumASCII(s[k-1]) {
			if v, ok := netBearerValueAt(s, lowered, k+len("authorization")); ok && netValueWord(s[v:netWordEnd(s, v, false)], true) {
				return true
			}
		}
		next := strings.Index(lowered[k+1:], "authorization")
		if next < 0 {
			break
		}
		k += 1 + next
	}
	return false
}

// netBearerValueAt: where the value starts after `authorization` ending at i: an optional closing quote, `:`,
// blanks, `bearer` and blanks; false when the header does not read that way.
func netBearerValueAt(s, lowered string, i int) (int, bool) {
	if i < len(s) && (s[i] == '"' || s[i] == '\'') {
		i++
	}
	if i >= len(s) || s[i] != ':' {
		return 0, false
	}
	i = lex.SkipBlanks(s, i+1)
	if !strings.HasPrefix(lowered[i:], "bearer") {
		return 0, false
	}
	v := lex.SkipBlanks(s, i+len("bearer"))
	if v == i+len("bearer") || v >= len(s) {
		return 0, false
	}
	return v, true
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

// netProgram: a program whose short option holds a password. apart: the value may also stand after a blank.
// anywhere: the option is read after any blank on the command, not only among the program's leading options,
// as the scrubber hides it there (a database or a quoted `-e` statement before it, the statement's own `;` too).
type netProgram struct {
	name, option    string
	apart, anywhere bool
}

var netPrograms = []netProgram{
	{"mysql", "-p", false, true}, {"mysqldump", "-p", false, true}, {"mysqladmin", "-p", false, false},
	{"mysqlimport", "-p", false, false}, {"mysqlcheck", "-p", false, false}, {"mysqlshow", "-p", false, false},
	{"mariadb", "-p", false, false}, {"mariadb-dump", "-p", false, false},
	{"sshpass", "-p", true, false}, {"redis-cli", "-a", true, false},
}

// netProgramOption: one of netPrograms, then on its command (to `;`, `|`, `&` or the line's end) its option with
// a value glued to it (or after a blank, where the program allows it) that is not a placeholder.
func netProgramOption(s string) bool {
	for _, p := range netPrograms {
		if netProgramLive(s, p) {
			return true
		}
	}
	return false
}

// netProgramLive: the program name, standing as a word, on a command (to netCommandEnd) that
// gives its option a live value among the program's own leading options (see netOptionLive), or anywhere on the
// command for a program read that way (see netOptionAnywhere).
func netProgramLive(s string, p netProgram) bool {
	name := p.name
	for k := strings.Index(s, name); k >= 0; {
		after := k + len(name)
		if (k == 0 || !netProgChar(s[k-1])) && (after >= len(s) || !netProgChar(s[after])) {
			end := netCommandEnd(s, after)
			if netOptionLive(s[after:end], p.option, p.apart) {
				return true
			}
			if p.anywhere {
				if qend := netCommandEndQuoted(s, after); netOptionAnywhere(s[after:qend], p.option) {
					return true
				}
			}
			k = end - 1 // the program again on the same command: its options were just read
		}
		next := strings.Index(s[k+1:], name)
		if next < 0 {
			break
		}
		k += 1 + next
	}
	return false
}

// netCommandEnd: the first `;`, `|`, `&` or line break at or after after, or len(s) when none.
func netCommandEnd(s string, after int) int {
	end := after
	for end < len(s) && strings.IndexByte(";|&\n", s[end]) < 0 {
		end++
	}
	return end
}

// netCommandEndQuoted: netCommandEnd, reading past a quoted argument closed on its line (`-e "use x; select 1"`).
func netCommandEndQuoted(s string, after int) int {
	end := after
	for end < len(s) && strings.IndexByte(";|&\n", s[end]) < 0 {
		if q := s[end]; q == '"' || q == '\'' {
			if k := strings.IndexByte(s[end+1:lex.LineEnd(s, end+1)], q); k >= 0 {
				end += k + 2
				continue
			}
		}
		end++
	}
	return end
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

// netOptionAnywhere: option written right after a blank anywhere on cmd, with a value glued to it.
func netOptionAnywhere(cmd, option string) bool {
	for i := 0; i+1 < len(cmd); i++ {
		if (cmd[i] != ' ' && cmd[i] != '\t') || !strings.HasPrefix(cmd[i+1:], option) {
			continue
		}
		v := i + 1 + len(option)
		e := v
		for e < len(cmd) && !lex.IsSpaceByte(cmd[e]) {
			e++
		}
		if netOptionValue(strings.Trim(cmd[v:e], "\"'")) {
			return true
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
		if netNamedValueAt(s, p, lastOpen > lastClose) {
			return true
		}
	}
	return false
}

// netNamedValueAt: the `:` or `=` at p, with a credential's name before it and a value after it. openBrace: an
// unclosed `{` before it on its line.
func netNamedValueAt(s string, p int, openBrace bool) bool {
	c := s[p]
	q, ok := netNameEnd(s, p)
	if !ok {
		return false
	}
	quoted := c == ':' && q > 0 && (s[q-1] == '"' || s[q-1] == '\'')
	if quoted {
		q--
	}
	n, name, ok := netStandingName(s, q, quoted, c == ':')
	if !ok {
		return false
	}
	v := p + 1
	for v < len(s) && (s[v] == ' ' || s[v] == '\t') {
		v++
	}
	if lex.LDIFBase64Colon(s, p) {
		v = lex.SkipBlanks(s, p+2)
	}
	yaml := c == ':' && netLineHead(s, n)
	flow := c == ':' && openBrace
	e := netWordEnd(s, v, flow)
	if c == ':' && v == p+1 && !quoted {
		// `name:value` with no blank: only a name after a blank, a line's start or `(` (an ARN, a key path or a
		// quoted string's head is not one), and a word holding a digit and no `.` unless a part of it reads as a
		// value (netDottedValue; a member chain the scrubber keeps otherwise), never a URL's `//`, `::` or Go's `:=`.
		standing := n == 0 || strings.IndexByte(" \t\n(", s[n-1]) >= 0
		word := strings.TrimRight(s[v:e], ".,;:!?)]}>*`\"'")
		return standing && v < len(s) && strings.IndexByte("/:=", s[v]) < 0 && (!strings.Contains(word, ".") || netDottedValue(word)) &&
			strings.ContainsAny(s[v:e], "0123456789") && netValueWord(s[v:e], false)
	}
	// A JSON key's value is a string; unquoted it is a number, a literal or no JSON at all.
	if quoted && (v >= len(s) || s[v] != '"' && s[v] != '\'' && s[v] != '\\') {
		return false
	}
	strong := netStrongName(name)
	return netValueWord(s[v:e], strong || yaml) || strong && !yaml && netInSentence(s, n) && netCapitalisedWord(s[v:e])
}

// netDottedValue: some part of the dotted word w, split at its dots, has upper case, lower case and a digit, or a
// digit between two letters (`Ab.CDEFgH2`), as no member's name does; the scrubber hides such a word whole.
func netDottedValue(w string) bool {
	for part := range strings.SplitSeq(w, ".") {
		hasLower := strings.IndexFunc(part, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0
		hasUpper := strings.IndexFunc(part, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0
		hasDigit := strings.ContainsAny(part, "0123456789")
		if hasLower && hasUpper && hasDigit || netDigitsInWord(part) {
			return true
		}
	}
	return false
}

// netDigitsInWord: a run of digits in p with an ASCII letter right before it and right after it.
func netDigitsInWord(p string) bool {
	for a := 1; a < len(p); a++ {
		if !lex.IsDigitASCII(p[a]) || !netLetter(p[a-1]) {
			continue
		}
		b := a
		for b < len(p) && lex.IsDigitASCII(p[b]) {
			b++
		}
		if b < len(p) && netLetter(p[b]) {
			return true
		}
		a = b
	}
	return false
}

func netLetter(c byte) bool { return lex.IsUpperASCII(c) || lex.IsLowerASCII(c) }

// netInSentence: the name starting at n stands after a blank, as a word of a sentence does, and not as a parameter
// (after `(` or `,`, blanks aside), whose capitalised word is its type (`def f(secret: Settings)`). After other
// punctuation (`[password: Authentication failed]`) the scrubber does not read a name.
func netInSentence(s string, n int) bool {
	if n == 0 || s[n-1] != ' ' && s[n-1] != '\t' {
		return false
	}
	for n > 0 && (s[n-1] == ' ' || s[n-1] == '\t') {
		n--
	}
	return n > 0 && s[n-1] != '(' && s[n-1] != ','
}

// netCapitalisedWord: mid-sentence after a strong name, a capitalised word of eight letters or more with no other
// capital (`see password: Hunterfox`), not prose. At a line's head or as a parameter it is a type (`secret: Settings`).
func netCapitalisedWord(w string) bool {
	w = strings.TrimRight(strings.TrimLeft(w, "\"'`"), ".,;:!?)\"'`")
	if len(w) < 8 || !lex.IsUpperASCII(w[0]) || netProse[strings.ToLower(w)] {
		return false
	}
	for i := 1; i < len(w); i++ {
		if !lex.IsLowerASCII(w[i]) {
			return false
		}
	}
	return true
}

// netStandingName: the credential's name that ends at q and stands as a word, inside its quotes when quoted: where
// it starts (at its opening quote when quoted) and the name; false when there is none.
func netStandingName(s string, q int, quoted, owned bool) (int, string, bool) {
	n := q
	for n > 0 && (lex.IsAlnumASCII(s[n-1]) || s[n-1] == '_' || s[n-1] == '-') {
		n--
	}
	if n == q {
		return 0, "", false
	}
	name := s[n:q]
	if quoted {
		if n == 0 || s[n-1] != s[q] {
			return 0, "", false
		}
		n--
	}
	if owned && !quoted {
		n = netOwnersStart(s, n)
	}
	if n > 0 && (lex.IsAlnumASCII(s[n-1]) || strings.IndexByte(".$@#/\\", s[n-1]) >= 0) {
		return 0, "", false // a member, a variable or a path: not a name standing as a word
	}
	if !vocab.IsCredentialName(name) {
		return 0, "", false
	}
	return n, name, true
}

// netOwnersStart: where the dotted owners before a name starting at n start (`db.` in `db.password:`), or n.
func netOwnersStart(s string, n int) int {
	for n > 1 && s[n-1] == '.' {
		o := n - 1
		for o > 0 && (lex.IsAlnumASCII(s[o-1]) || s[o-1] == '_' || s[o-1] == '-') {
			o--
		}
		if o == n-1 || !lex.IsLowerASCII(s[o]) && !lex.IsUpperASCII(s[o]) && s[o] != '_' {
			return n
		}
		n = o
	}
	return n
}

// netNameEnd: where the name before the `:` or `=` at p ends: before the blanks of a `:` or of a spaced `=`;
// false for `==`, `=~` and an `=` without a blank on both sides.
func netNameEnd(s string, p int) (int, bool) {
	q := p
	if s[p] == ':' {
		for q > 0 && (s[q-1] == ' ' || s[q-1] == '\t') {
			q--
		}
	}
	if s[p] == '=' {
		if p+1 < len(s) && (s[p+1] == '=' || s[p+1] == '~') {
			return 0, false
		}
		for q > 0 && (s[q-1] == ' ' || s[q-1] == '\t') {
			q--
		}
		if q == p || p+1 >= len(s) || (s[p+1] != ' ' && s[p+1] != '\t') {
			return 0, false // `NAME=value` is the assignment check's
		}
	}
	return q, true
}

// netWordEnd: where the word at v ends: a blank, netMaxWord bytes, or in a flow mapping a `,` or `}`.
func netWordEnd(s string, v int, flow bool) int {
	e := v
	for e < len(s) && e-v < netMaxWord && !lex.IsSpaceByte(s[e]) && (!flow || s[e] != ',' && s[e] != '}') {
		e++
	}
	return e
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
// placeholder, a reference or code, and either letters mixed with digits, or letters only and long. A hash or
// password behind a scheme tag (`{SSHA}…`, `{CRYPT}$6$…`) is a value whatever its shape.
func netValueWord(w string, strong bool) bool {
	for _, open := range []string{"**", "\\\"", "\"", "'", "`", "(", "["} {
		w = strings.TrimPrefix(w, open)
	}
	if lex.SchemeTagEnd(w, 0) > 0 {
		return true
	}
	w = strings.TrimRight(w, ".,;:!?)]}>*`\"'\\")
	if w == "" || lex.OnlyPlaceholders(w) || netReference(w) || strings.ContainsAny(w[:1], "%{|>&*!~<[") ||
		netProse[strings.ToLower(w)] {
		return false
	}
	// `@` `#` `,` `$` hold a value's parts together only in a word with no `.`: with one it is a member chain, a host
	// or an image (`self.tok,self.exp2`, `ghcr.io/x@sha256`), which the scrubber keeps. A crypt hash's salt holds `.`.
	glue := strings.ContainsAny(w[1:], "@#,$") || w[0] == '$'
	if glue && strings.Contains(w, ".") && !netCryptHead(w) {
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
		case i > 0 && (ch == '@' || ch == '#' || ch == ',' || ch == '$'):
			seps++ // inside a word, part of the value (`Ab@x9…`, `Ab#x9…`, a bcrypt hash's `$`)
		case i == 0 && ch == '$':
			seps++ // not a reference (netReference): a value that opens with `$`
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

// netReference: a word that is a shell or template reference, not a value: `${x}`, `$(cmd)`, `$$`, `$1`, `$5k`, or a
// variable's name (`$TOKEN`, `$myPassword`). A crypt hash (`$2b$12$...`, `$bcrypt-sha256$...`) or a name mixing cases
// and digits is a value.
func netReference(w string) bool {
	if w == "" || w[0] != '$' || netCryptHead(w) {
		return false
	}
	if len(w) == 1 || w[1] == '{' || w[1] == '(' || w[1] == '$' {
		return true
	}
	upper, lower, digit := false, false, false
	j := 1
	for ; j < len(w) && (lex.IsAlnumASCII(w[j]) || w[j] == '_'); j++ {
		upper = upper || lex.IsUpperASCII(w[j])
		lower = lower || lex.IsLowerASCII(w[j])
		digit = digit || lex.IsDigitASCII(w[j])
	}
	if j < len(w) && (lex.IsWordAt(w, j) || w[j] == '$') {
		return false
	}
	if lex.IsDigitASCII(w[1]) {
		return true
	}
	return !upper || !lower || !digit
}

// netCryptHead: w holds a crypt hash's head (`$2b$`, `$argon2id$`, `$bcrypt-sha256$`) anywhere, as the detector
// reads one after any prefix (`argon2$argon2id$`, `bcrypt_sha256$$2b$`). Any `$x$` counts: a reference or a member
// chain holding one reads as a value, which refuses rather than sends.
func netCryptHead(w string) bool {
	for i := 0; i+2 < len(w); i++ {
		if w[i] != '$' || !lex.IsAlnumASCII(w[i+1]) {
			continue
		}
		j := i + 2
		for j < len(w) && (lex.IsAlnumASCII(w[j]) || w[j] == '_' || w[j] == '-') {
			j++
		}
		if j < len(w) && w[j] == '$' {
			return true
		}
	}
	return false
}
