package scrub

import (
	"math"
	"strings"
	"testing"
)

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

// Each row is a way a caller got a clean or whole answer for something that was not checked or kept readable
// (found by reading the code against the README's contract).
func TestEdgesRefuseOrKeepReadable(t *testing.T) {
	d := fakeDenylist(t)
	token := "ghp_" + "aB3dE5gH7jK9mN1pQrStUvWxYz0123456789" // split so the release secret scan does not flag a fake token
	t.Run("a typed map is audited as JSON", func(t *testing.T) {
		if hits := AuditValue(map[string]string{"k": token}, d); len(hits) == 0 {
			t.Error("a token in a map[string]string passed the audit")
		}
		if hits := AuditValue([]string{token}, d); len(hits) == 0 {
			t.Error("a token in a []string passed the audit")
		}
	})
	t.Run("a value with no JSON encoding is refused", func(t *testing.T) {
		if hits := AuditValue(make(chan int), d); len(hits) != 1 || hits[0] != "unreadable" {
			t.Errorf("got %v, want [unreadable]", hits)
		}
	})
	t.Run("text over the cap is refused", func(t *testing.T) {
		if hits := Audit(strings.Repeat("a", MaxAuditBytes+1), d); len(hits) != 1 || hits[0] != "unreadable" {
			t.Errorf("got %v, want [unreadable]", hits)
		}
	})
	t.Run("the README's payload with a version parses", func(t *testing.T) {
		if _, err := ParseDenylist([]byte(`{"version": 1, "identities": [{"literal": "Zoë Quillfen", "role": "owner"}], "vendors": []}`), 1); err != nil {
			t.Error(err)
		}
		if _, err := ParseDenylist([]byte(`{"version": 2, "identities": [{"literal": "Zoë Quillfen", "role": "owner"}], "vendors": []}`), 1); err == nil {
			t.Error("a payload version that differs from the one given was accepted")
		}
	})
	t.Run("a limit below the marker sends nothing, and a huge one does not overflow", func(t *testing.T) {
		if got := Scrub("hello world, this is long enough to cut", d, 3); got != "" {
			t.Errorf("limit 3: got %q, want empty", got)
		}
		if got := Scrub("hello world", d, math.MaxInt); got != "hello world" {
			t.Errorf("limit MaxInt: got %q", got)
		}
	})
}
