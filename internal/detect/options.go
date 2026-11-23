package detect

import (
	"regexp"
	"strings"

	"github.com/0xbew/scrub/internal/lex"
)

// --- program options (R2) ----------------------------------------------------------------

// CommandArgs: positions after a space or tab inside the command that starts at p, up to
// an unquoted `|` `;` `&` or the line end (continuations join), quoted arguments read whole.
func CommandArgs(s string, p int, program string) []int {
	var out []int
	i := p + len(program)
	for i < len(s) {
		if n := lex.ContAt(s, i); n > 0 {
			i += n
			continue
		}
		c := s[i]
		if c == '\n' || c == '|' || c == ';' || c == '&' {
			break
		}
		if (i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || (i >= 2 && s[i-1] == '\n' && s[i-2] == '\\')) && i > p {
			out = append(out, i)
		}
		i = commandArgSkip(s, i)
	}
	return out
}

// commandArgSkip: where reading goes on after the byte at i of a command: past an escaped
// byte, or past a quoted argument closed on its line, else the next byte.
func commandArgSkip(s string, i int) int {
	switch s[i] {
	case '\\':
		i += 2
	case '\'':
		if k := strings.IndexByte(s[i+1:lex.LineEnd(s, i+1)], '\''); k >= 0 {
			i += k + 2
		} else {
			i++
		}
	case '"':
		e := lex.DqEndLine(s, i)
		if e > i+1 && s[e-1] == '"' {
			i = e
		} else {
			i++
		}
	default:
		i++
	}
	return i
}

// Programs: every mention of a program, at a word boundary.
func Programs(s, program string) []int {
	var out []int
	low := lex.AsciiLower(s)
	for at := 0; ; {
		k := strings.Index(low[at:], program)
		if k < 0 {
			return out
		}
		p := at + k
		at = p + 1
		if p > 0 && lex.WordBefore(s, p) {
			continue
		}
		if lex.IsWordAt(s, p+len(program)) {
			continue
		}
		out = append(out, p)
	}
}

type passwordOption struct {
	Program  string
	Option   string
	Attached bool
	leftDash bool // the program must not follow a `-` (`login` in `docker login`, not `x-login`)
}

var PasswordOptions = []passwordOption{
	{"login", "-p", true, true},
	{"sshpass", "-p", true, false},
	{"redis-cli", "-a", false, false},
	{"openssl", "-k", false, false},
	{"openssl", "-K", false, false},
}

func (c *Scan) programOptions() {
	s := c.S
	for _, po := range PasswordOptions {
		for _, p := range Programs(s, po.Program) {
			if po.leftDash && p > 0 && s[p-1] == '-' {
				continue
			}
			for _, a := range CommandArgs(s, p, po.Program) {
				c.hideOptionValue(po, a)
			}
		}
	}
	c.curlUser()
	c.opensslPass()
	c.mysql()
	c.secretSet()
	c.npmAuth()
}

// hideOptionValue: hides the value of po's option when the argument at a is that option, its
// value attached or after blanks as po allows, and the value is not another option.
func (c *Scan) hideOptionValue(po passwordOption, a int) {
	s := c.S
	if !strings.HasPrefix(s[a:], po.Option) {
		return
	}
	k := a + len(po.Option)
	v := lex.SkipBlanksConts(s, k)
	if !po.Attached && v == k {
		return
	}
	if v >= len(s) || !NotAnOption(s, v) {
		return
	}
	c.hideValue(v, lex.ValueEnd(s, v))
}

// curlUser: `curl -u user:password` and its spellings; everything after the user's colon.
func (c *Scan) curlUser() {
	s := c.S
	for _, p := range Programs(s, "curl") {
		for _, a := range CommandArgs(s, p, "curl") {
			if s[a] != '-' {
				continue
			}
			v := curlUserValueAt(s, a)
			if v < 0 || v >= len(s) {
				continue
			}
			c.userPassword(v)
		}
	}
}

// curlUserValueAt: where the value of curl's user option at a starts; -1 when a is no user
// option or it has no value.
func curlUserValueAt(s string, a int) int {
	switch {
	case strings.HasPrefix(s[a:], "--user") || strings.HasPrefix(s[a:], "--proxy-user"):
		return curlLongUserValue(s, a)
	default:
		return curlShortUserValue(s, a)
	}
}

// curlLongUserValue: the value of `--user` or `--proxy-user` at a, after `=` or blanks; -1
// when neither follows.
func curlLongUserValue(s string, a int) int {
	v := -1
	k := a + len("--user")
	if strings.HasPrefix(s[a:], "--proxy-user") {
		k = a + len("--proxy-user")
	}
	if k < len(s) && s[k] == '=' {
		v = k + 1
	} else if e := lex.SkipBlanksConts(s, k); e > k {
		v = e
	}
	return v
}

// curlShortUserValue: the value of the `-u`/`-U` among the short options at a, glued or after
// blanks; -1 when there is none.
func curlShortUserValue(s string, a int) int {
	v := -1
	j := a + 1
	for j < len(s) && (lex.IsLowerASCII(s[j]) || lex.IsUpperASCII(s[j])) && s[j] != 'u' && s[j] != 'U' {
		j++
	}
	if j >= len(s) || (s[j] != 'u' && s[j] != 'U') {
		return -1
	}
	k := j + 1
	if k < len(s) && (lex.IsLowerASCII(s[k]) || lex.IsUpperASCII(s[k])) {
		// glued user (`-uadmin:x`, the proxy's `-Uadmin:x`, and after other flags, `-kuadmin:x`: curl's
		// short options combine, and the one that takes a value takes the rest of the word)
		return k
	}
	if e := lex.SkipBlanksConts(s, k); e > k {
		v = e
	} else if k < len(s) && !lex.IsSpaceByte(s[k]) && s[k] != '-' {
		v = k
	}
	return v
}

// userPassword: in a `user:password` argument at v, hide everything after the user's colon.
func (c *Scan) userPassword(v int) {
	s := c.S
	if s[v] == '"' || s[v] == '\'' {
		var end int
		if s[v] == '"' {
			end = lex.DqEndLine(s, v)
		} else {
			end = lex.SqEnd(s, v)
		}
		colon := strings.IndexByte(s[v:end], ':')
		if colon >= 0 {
			body := end
			if end > v+1 && s[end-1] == s[v] {
				body = end - 1
			}
			c.hideValue(v+colon+1, body)
			// A part glued after the closing quote is the same word.
			if body < end {
				c.hideValue(end, lex.ValueEnd(s, end))
			}
			return
		}
	}
	end := lex.ValueEnd(s, v)
	// The user may be quoted on its own (`"admin":x`); after its colon everything is the value.
	i := v
	for i < end {
		switch s[i] {
		case '"':
			i = lex.DqEndLine(s, i)
			continue
		case '\'':
			i = lex.SqEnd(s, i)
			continue
		case '\\':
			i += 2
			continue
		case ':':
			c.hideValue(i+1, end)
			return
		}
		i++
	}
}

var OpensslPassRx = regexp.MustCompile(`-pass(?:in|out|word)?`)

func (c *Scan) opensslPass() {
	s := c.S
	for _, m := range OpensslPassRx.FindAllStringIndex(s, -1) {
		if m[0] > 0 && (lex.WordBefore(s, m[0]) || s[m[0]-1] == '-') {
			continue
		}
		v := opensslValueAt(s, m[1])
		if v < 0 {
			continue
		}
		c.hideOpensslPass(v)
	}
}

// opensslValueAt: where the value of an openssl password option ending at k starts, after `=`
// or blanks and continuations; -1 when neither separates it or nothing follows.
func opensslValueAt(s string, k int) int {
	var v int
	if k < len(s) && s[k] == '=' {
		v = k + 1
	} else if e := lex.SkipBlanksConts(s, k); e > k {
		v = e
	} else {
		return -1
	}
	if v >= len(s) {
		return -1
	}
	return v
}

// hideOpensslPass: hides the password of a `pass:` value at v, quoted or bare.
func (c *Scan) hideOpensslPass(v int) {
	s := c.S
	if (s[v] == '"' || s[v] == '\'') && strings.HasPrefix(strings.ToLower(s[v+1:]), "pass:") {
		end := lex.DqEndLine(s, v)
		if s[v] == '\'' {
			end = lex.SqEnd(s, v)
		}
		body := end
		if end > v+1 && s[end-1] == s[v] {
			body = end - 1
		}
		c.hideValue(v+6, body)
		return
	}
	if strings.HasPrefix(strings.ToLower(s[v:]), "pass:") {
		w := SkipConts(s, v+5)
		c.hideValue(w, lex.ValueEnd(s, w))
	}
}

func SkipConts(s string, i int) int {
	for {
		n := lex.ContAt(s, i)
		if n == 0 {
			return i
		}
		i += n
	}
}

// mysql: every attached `-p` in a mysql or mysqldump command.
func (c *Scan) mysql() {
	s := c.S
	for _, prog := range []string{"mysqldump", "mysql"} {
		for _, p := range Programs(s, prog) {
			c.mysqlPasswords(s[:commandEnd(s, p)], p)
		}
	}
}

// commandEnd: the end of the command that starts at p: the first line break, `|`, `;` or `&` outside a
// quoted argument closed on its line (`-e "use x; select 1" -pSECRET`), continuations joined.
func commandEnd(s string, p int) int {
	end := p
	for end < len(s) {
		if n := lex.ContAt(s, end); n > 0 {
			end += n
			continue
		}
		ch := s[end]
		if ch == '\n' || ch == '|' || ch == ';' || ch == '&' {
			break
		}
		end = commandArgSkip(s, end)
	}
	return min(end, len(s))
}

// mysqlPasswords: hides what follows every blank and `-p` in seg from p on, to the value's end.
func (c *Scan) mysqlPasswords(seg string, p int) {
	for i := p; i+2 < len(seg); i++ {
		if lex.IsSpaceByte(seg[i]) && seg[i+1] == '-' && seg[i+2] == 'p' {
			v := i + 3
			c.hideValue(v, lex.ValueEnd(seg, v))
		}
	}
}

var secretSetRx = regexp.MustCompile(`(?i)\bsecrets? set\b`)

// secretSet: `secret set NAME ... --body VALUE` / `-b VALUE` / `-bVALUE`.
func (c *Scan) secretSet() {
	s := c.S
	for _, m := range secretSetRx.FindAllStringIndex(s, -1) {
		end := contLineEnd(s, m[1])
		for i := m[1]; i < end; i++ {
			if k, ok := secretBodyAt(s, i); ok {
				c.hideValue(k, lex.ValueEnd(s, k))
			}
		}
	}
}

// contLineEnd: the end of the line from i, its continuations (`\` before a line break) joined.
func contLineEnd(s string, i int) int {
	end := i
	for end < len(s) {
		if n := lex.ContAt(s, end); n > 0 {
			end += n
			continue
		}
		if s[end] == '\n' {
			break
		}
		end++
	}
	return end
}

// secretBodyAt: the value of an option opening with `--body` or `-b` after the space at i (so `--bodyfile` and
// `-branch` too): glued (`-bVALUE`), after `=`, or after blanks and continuations; false when none stands there.
func secretBodyAt(s string, i int) (int, bool) {
	if !lex.IsSpaceByte(s[i]) || i+2 >= len(s) || s[i+1] != '-' {
		return 0, false
	}
	var k int
	switch {
	case strings.HasPrefix(s[i+1:], "--body"):
		k = i + 7
	case s[i+2] == 'b':
		k = i + 3
	default:
		return 0, false
	}
	if k < len(s) && s[k] == '=' {
		return k + 1, true
	}
	return skipSpacesConts(s, k), true
}

// skipSpacesConts: past the white space (line breaks too) and continuations from k.
func skipSpacesConts(s string, k int) int {
	for k < len(s) {
		if lex.IsSpaceByte(s[k]) {
			k++
			continue
		}
		if n := lex.ContAt(s, k); n > 0 {
			k += n
			continue
		}
		break
	}
	return k
}

var NpmAuthRx = regexp.MustCompile(`(?i):_(?:authToken|auth|password)["']?`)

func (c *Scan) npmAuth() {
	s := c.S
	for _, m := range NpmAuthRx.FindAllStringIndex(s, -1) {
		k := m[1]
		v := lex.SkipBlanksConts(s, k)
		if v == k || v >= len(s) || !NotAnOption(s, v) {
			continue
		}
		c.hideValue(v, lex.ValueEnd(s, v))
	}
}
