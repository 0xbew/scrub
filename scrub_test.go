package scrub

import "testing"

// Classifier cases are the names and values from harness failures; each expected value is the
// Python oracle's (scrub_names.is_credential_name, looks_secret), not this package's.
func TestClassifiersAgreeWithTheOracle(t *testing.T) {
	names := []struct {
		name string
		want bool
	}{
		{"accesskey", true}, {"ACCESSKEYS", true}, {"credentialss", true}, {"hotp", true}, {"DSNS", true},
		{"auths", true}, {"authorization", true}, {"passwd", true}, {"api_key", true}, {"pin", true}, {"otp", true},
		{"n", false}, {"tokenizer", false}, {"author", false}, {"spinner", false}, {"password-file", false},
		{"cookie", false}, {"secret_name", false}, {"keyboard", false},
	}
	for _, c := range names {
		if got := IsCredentialName(c.name); got != c.want {
			t.Errorf("IsCredentialName(%q) = %v, oracle %v", c.name, got, c.want)
		}
	}
	values := []struct {
		value string
		want  bool
	}{
		{"aB3dE5gH7jK9mN1p", true}, {"Qa7mXv2pL9Rb8nYw", true}, {"abcdefghijklmnop1234", true},
		{"fe5f80f77d5fa3be", true}, {"2026-11-04T00:00:00Z", true},
		{"Vq7zLmQ", false}, {"Zq9Kx7LmQw", false}, {"hunter2", false}, {"<redacted>", false},
		{"hello world", false}, {"hello_world_config", false}, {"/usr/local/bin/python3", false},
	}
	for _, c := range values {
		if got := LooksSecret(c.value); got != c.want {
			t.Errorf("LooksSecret(%q) = %v, oracle %v", c.value, got, c.want)
		}
	}
}

// The readings' offset maps: each decoded byte must name the source bytes a receiver decoded
// it from, so a value found there hides its source. Cases are the phase-2 leak shapes.
func TestReadingsMapEachByteToItsSource(t *testing.T) {
	type span struct{ lo, hi int }
	cases := []struct {
		name   string
		src    string
		read   func(*reading) *reading
		text   string
		at     int  // a byte of text
		from   span // the source span it came from
		joined bool
	}{
		// A JSON string's `\n` is a line break: the break stands for both source bytes.
		{"json line break", `ls\n--token x`, func(r *reading) *reading { return r.unescape(true) }, "ls\n--token x", 2, span{2, 4}, false},
		// Read as a plain escape it is the letter, and the words either side run together.
		{"plain escape", `ls\n--token x`, func(r *reading) *reading { return r.unescape(false) }, "lsn--token x", 2, span{2, 4}, true},
		// A JSON string's unicode escape of `=` is `=`.
		{"json unicode", "token\\u003dabc", func(r *reading) *reading { return r.unescape(true) }, "token=abc", 5, span{5, 11}, false},
		// An escaped quote is its backslash and itself.
		{"escaped quote", `{\"k\": 1}`, func(r *reading) *reading { return r.unescape(false) }, `{"k": 1}`, 1, span{1, 3}, false},
		// Percent-encoded: `%22` is one quote of three source bytes; `+` is a space.
		{"percent", `%22a+b%22`, func(r *reading) *reading { return r.percentDecode() }, `"a b"`, 4, span{6, 9}, false},
		// A JSON string's \u escape past ASCII is its character's UTF-8 bytes, each from the whole escape; a
		// surrogate pair is one character, from both escapes.
		{"json unicode past ASCII", "a\\u00e9\\ud83d\\ude00b", func(r *reading) *reading { return r.unescape(true) }, "aé😀b", 1, span{1, 7}, false},
		{"json surrogate pair", "a\\u00e9\\ud83d\\ude00b", func(r *reading) *reading { return r.unescape(true) }, "aé😀b", 3, span{7, 19}, false},
		{"json unicode past ASCII, last byte", "a\\u00e9\\ud83d\\ude00b", func(r *reading) *reading { return r.unescape(true) }, "aé😀b", 2, span{1, 7}, false},
		{"json surrogate pair, last byte", "a\\u00e9\\ud83d\\ude00b", func(r *reading) *reading { return r.unescape(true) }, "aé😀b", 6, span{7, 19}, false},
	}
	for _, c := range cases {
		r := c.read(rawReading(c.src))
		if r.text != c.text {
			t.Errorf("%s: text %q, want %q", c.name, r.text, c.text)
			continue
		}
		if lo, hi := r.source(c.at, c.at+1); lo != c.from.lo || hi != c.from.hi {
			t.Errorf("%s: byte %d from [%d,%d), want [%d,%d)", c.name, c.at, lo, hi, c.from.lo, c.from.hi)
		}
		if r.joined != c.joined {
			t.Errorf("%s: joined %v, want %v", c.name, r.joined, c.joined)
		}
	}
}

// A quoted value ends at a quote written as its opener, past a line break written as a
// continuation. Both are phase-2 leaks: the value's tail was sent.
func TestAQuotedValueEndsAtItsOwnClosingQuote(t *testing.T) {
	cases := []struct {
		name, src string
		read      func(*reading) *reading
		open      int // the opening quote in the reading
		want      int // the end of the value in the reading (just past its closing quote)
	}{
		// `%22TOKEN%22%3A%22abc"Vq7zLmQ%22`: the raw `"` is the value's, `%22` closes it.
		{"raw quote in an encoded value", `%22abc"Vq7zLmQ%22 x`, func(r *reading) *reading { return r.percentDecode() }, 0, 13},
		// `\"zq9\<newline>tail\"` one level down: the escaped break continues the value.
		{"continued line break", "\\\"zq9\\\ntail\\\" x", func(r *reading) *reading { return r.unescape(false) }, 0, 10},
		// A quote written as the opener closes it: nothing more is read.
		{"closed", `"abc" "def"`, func(r *reading) *reading { return r }, 0, 5},
	}
	for _, c := range cases {
		r := c.read(rawReading(c.src))
		if got := r.quotedEnd(r.text, c.open, dqEndLine); got != c.want {
			t.Errorf("%s: %q ends at %d, want %d", c.name, r.text, got, c.want)
		}
	}
}

// Lexer extents, with the expected end from shell and object-literal grammar.
func TestValueExtents(t *testing.T) {
	cases := []struct {
		name string
		got  func() int
		want int
	}{
		// bash: quoted and bare parts glue into one word.
		{"glued shell word", func() int { return valueEnd(`"ab"cd'ef' x`, 0) }, 10},
		// bash: an escaped space continues the word.
		{"escaped space", func() int { return valueEnd(`ab\ cd x`, 0) }, 6},
		// An object literal's value ends before the `}` that closes the literal.
		{"flow words", func() int { return colonWords("ab Vq7zLmQ}", 0, true, false) }, 11},
		// A double-quoted string honours its escapes to the closing quote on its line.
		{"dq escapes", func() int { return dqEndLine(`"a\"b" c`, 0) }, 6},
		// A `]` inside a string does not close the array (review finding: the element after it
		// was sent).
		{"array past a quoted bracket", func() int { return arrayEnd(`["x]", "abc"] y`, 0) }, 12},
		// Unclosed, it runs to the line end.
		{"dq unclosed", func() int { return dqEndLine("\"ab\ncd", 0) }, 3},
		// bash: a heredoc opener is `<<`, an optional `-`, and its word, quoted or not; the rest
		// of the line is the command's (phase-2 brief leak: its literals were not read).
		{"heredoc opener", func() int { return heredocOpenerEnd(`<<-"EOF" | x`, 0) }, 8},
	}
	for _, c := range cases {
		if got := c.got(); got != c.want {
			t.Errorf("%s: end %d, want %d", c.name, got, c.want)
		}
	}
}

// Phase-3 leak classes on real data, as synthetic shapes. Each failed on the previous code: its
// output was refused by Python's audit (the oracle) or by this package's own. The expected
// output is the Python oracle's, except where noted.
func TestOutputsThePythonAuditPasses(t *testing.T) {
	cases := []struct{ name, in, want string }{
		// A quoted assignment inside another quoted word, rendered `'pin=<redacted> "<redacted>"'`:
		// Python's audit reads the quote between two placeholders as part of the value.
		{"quoted assignment re-read", `for v in ['pin=1234','"otp": "123456"']: pass`, `for v in ['pin=<redacted>']: pass`},
		// A password-family flag's value is the word at a here-string or heredoc operator.
		{"here-string operator", `f('--token <<< ', n)`, `f('--token <redacted> <redacted>`},
		{"heredoc opener on one line", "a = f('--token <<EOF ', n),\nb = 2", "a = f('--token <redacted> ', n),\nb = 2"},
		// Go-stricter than Python, which sends it: the shell word `X-Token:'zq9xk'` holds the value,
		// and this package's audit refused the old output.
		{"unquoted header opening a quoted part", `curl -H X-Token:'zq9xk'`, `curl -H X-Token:'<redacted>'`},
		// Go-stricter than Python, which sends it: mid-sentence after a strong credential name a plain word is
		// the value (an owner decision; a weaker name keeps it as prose).
		{"plain word after a strong name mid-sentence", `see password: letmein here`, `see password: <redacted> here`},
	}
	for _, c := range cases {
		got := Scrub(c.in, NoDenylist, 4000)
		if got != c.want {
			t.Errorf("%s: Scrub = %q, want %q", c.name, got, c.want)
		}
		if hits := Audit(got, NoDenylist); len(hits) > 0 {
			t.Errorf("%s: own audit refuses the output: %v", c.name, hits)
		}
	}
}

// Audit false positives on scrubbed text, where the Python oracle's audit passes. Both refused a
// clean output on real data, so the send was blocked for nothing.
func TestAuditPassesWhatThePythonAuditPasses(t *testing.T) {
	cases := []struct{ name, in string }{
		// `---DSN` is a separator line, not a flag: a name must follow the dashes.
		{"three dashes", `echo "---DSN start---"`},
		// A backtick value across diff rows: a line break and the next row's marker hold nothing.
		{"value across diff rows", "api_key = <redacted>`<redacted>\n+<redacted>`"},
	}
	for _, c := range cases {
		if hits := Audit(c.in, NoDenylist); len(hits) > 0 {
			t.Errorf("%s: Audit = %v, want none", c.name, hits)
		}
	}
}

// Values the audit refuses must be values the scrubber hides, or the send is blocked with the
// value still in it. Review findings: the previous scrubber kept each of these.
func TestScrubberHidesWhatItsAuditRefuses(t *testing.T) {
	cases := []struct{ name, in, want string }{
		// A receiver reads `--passwd` inside `---passwd` (the Python oracle hides it too).
		{"more dashes before a password flag", `---passwd zq9xkT7w-x`, `---passwd <redacted>`},
		// A truncated quoted header whose value opens the other quote.
		{"unclosed outer quote", `curl -H 'X-Api-Key:"zq9xkT7w1"`, `curl -H 'X-Api-Key:"<redacted>"`},
		// A quoted name and a literal inside another quoted word.
		{"quoted name argument in a quoted word", `echo '"password", "zq9xkT7w"'`, `echo '"password", "<redacted>"'`},
		// A heredoc after a credential's `NAME=` or `name:`: its body was sent, a blank first line or not.
		{"heredoc after a name and =", "DB_PASSWORD=<<EOF\n\nzq9xkT7w\nEOF", "DB_PASSWORD=<redacted>\n<redacted>\nEOF"},
		{"heredoc after a name and a colon", "token: <<EOF\nzq9xkT7w\nEOF", "token: <redacted>\n<redacted>\nEOF"},
	}
	for _, c := range cases {
		got := Scrub(c.in, NoDenylist, 4000)
		if got != c.want {
			t.Errorf("%s: Scrub = %q, want %q", c.name, got, c.want)
		}
		if hits := Audit(c.in, NoDenylist); len(hits) == 0 {
			t.Errorf("%s: the audit passes the raw text", c.name)
		}
		if hits := Audit(got, NoDenylist); len(hits) > 0 {
			t.Errorf("%s: own audit refuses the output: %v", c.name, hits)
		}
	}
}
