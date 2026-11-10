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
		switch c {
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
	}
	return out
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
				if !strings.HasPrefix(s[a:], po.Option) {
					continue
				}
				k := a + len(po.Option)
				v := lex.SkipBlanksConts(s, k)
				if !po.Attached && v == k {
					continue
				}
				if v >= len(s) || !NotAnOption(s, v) {
					continue
				}
				c.hideValue(v, lex.ValueEnd(s, v))
			}
		}
	}
	c.curlUser()
	c.opensslPass()
	c.mysql()
	c.secretSet()
	c.npmAuth()
}

// curlUser: `curl -u user:password` and its spellings; everything after the user's colon.
func (c *Scan) curlUser() {
	s := c.S
	for _, p := range Programs(s, "curl") {
		for _, a := range CommandArgs(s, p, "curl") {
			if s[a] != '-' {
				continue
			}
			v := -1
			switch {
			case strings.HasPrefix(s[a:], "--user") || strings.HasPrefix(s[a:], "--proxy-user"):
				k := a + len("--user")
				if strings.HasPrefix(s[a:], "--proxy-user") {
					k = a + len("--proxy-user")
				}
				if k < len(s) && s[k] == '=' {
					v = k + 1
				} else if e := lex.SkipBlanksConts(s, k); e > k {
					v = e
				}
			default:
				j := a + 1
				for j < len(s) && (lex.IsLowerASCII(s[j]) || lex.IsUpperASCII(s[j])) && s[j] != 'u' && s[j] != 'U' {
					j++
				}
				if j >= len(s) || (s[j] != 'u' && s[j] != 'U') {
					continue
				}
				k := j + 1
				if k < len(s) && (lex.IsLowerASCII(s[k]) || lex.IsUpperASCII(s[k])) {
					// glued user (`-uadmin:x`, the proxy's `-Uadmin:x`, and after other flags, `-kuadmin:x`: curl's
					// short options combine, and the one that takes a value takes the rest of the word)
					v = k
					break
				}
				if e := lex.SkipBlanksConts(s, k); e > k {
					v = e
				} else if k < len(s) && !lex.IsSpaceByte(s[k]) && s[k] != '-' {
					v = k
				}
			}
			if v < 0 || v >= len(s) {
				continue
			}
			c.userPassword(v)
		}
	}
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
		k := m[1]
		var v int
		if k < len(s) && s[k] == '=' {
			v = k + 1
		} else if e := lex.SkipBlanksConts(s, k); e > k {
			v = e
		} else {
			continue
		}
		if v >= len(s) {
			continue
		}
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
			continue
		}
		if strings.HasPrefix(strings.ToLower(s[v:]), "pass:") {
			w := SkipConts(s, v+5)
			c.hideValue(w, lex.ValueEnd(s, w))
		}
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
				end++
			}
			seg := s[:end]
			for i := p; i+2 < len(seg); i++ {
				if lex.IsSpaceByte(seg[i]) && seg[i+1] == '-' && seg[i+2] == 'p' {
					v := i + 3
					c.hideValue(v, lex.ValueEnd(seg, v))
				}
			}
		}
	}
}

var secretSetRx = regexp.MustCompile(`(?i)\bsecrets? set\b`)

// secretSet: `secret set NAME ... --body VALUE` / `-b VALUE` / `-bVALUE`.
func (c *Scan) secretSet() {
	s := c.S
	for _, m := range secretSetRx.FindAllStringIndex(s, -1) {
		end := m[1]
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
		for i := m[1]; i < end; i++ {
			if !lex.IsSpaceByte(s[i]) || i+2 >= len(s) || s[i+1] != '-' {
				continue
			}
			var k int
			switch {
			case strings.HasPrefix(s[i+1:], "--body"):
				k = i + 7
			case s[i+2] == 'b':
				k = i + 3
			default:
				continue
			}
			if k < len(s) && s[k] == '=' {
				k++
			} else {
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
			}
			c.hideValue(k, lex.ValueEnd(s, k))
		}
	}
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
