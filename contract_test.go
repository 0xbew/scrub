package scrub

import (
	"strings"
	"testing"
)

// Contract fixes (SCRUBBER.md, measures (a)-(d)). Every case is synthetic: a canary shape the gate's planted
// canaries found surviving, rebuilt by hand. Each failed on the code before its fix. The expected value is the
// contract's: no 6 characters of the body in the output, and the output passes this package's own audit.

// fakeDenylist: names no real list holds.
func fakeDenylist(t *testing.T) *Denylist {
	t.Helper()
	d, err := ParseDenylist([]byte(`{"identities": [{"literal": "Zoë Quillfen", "role": "teammate"},
		{"literal": "Vorbel Trinquas", "role": "owner"}], "vendors": ["Plimbrax"]}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// u: a JSON \\u escape, written out.
func u(hex string) string { return "\\" + "u" + hex }

func assertHidden(t *testing.T, name, in, body string, d *Denylist) {
	t.Helper()
	out := Scrub(in, d, 100000)
	for i := 0; i+6 <= len(body); i++ {
		if strings.Contains(out, body[i:i+6]) {
			t.Errorf("%s: %q survives in %q", name, body[i:i+6], out)
			return
		}
	}
	if hits := Audit(out, d); len(hits) > 0 {
		t.Errorf("%s: the audit refuses the output %q: %v", name, out, hits)
	}
}

// The cheap decodes of DESIGN section 9 are readings: \u past ASCII and surrogate pairs, \xNN, octal, HTML
// entities, a second level of percent-encoding, and fullwidth letters. A receiver decodes each; before this,
// the scrubber read none of them.
func TestCheapDecodesAreRead(t *testing.T) {
	d := fakeDenylist(t)
	cases := []struct{ name, in, body string }{
		{"\\u past ASCII in a name", `"author": "Zo` + u("00eb") + ` Quillfen"`, "Quillfen"},
		{"\\xNN token", `printf '\x67\x68\x70\x5f\x61\x42\x33\x64\x45\x35\x67\x48\x37\x6a\x4b\x39\x6d\x4e\x31\x70\x51\x72\x53\x74\x55\x76\x57\x78\x59\x7a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39'`, "aB3dE5gH7jK9mN1pQrStUvWxYz0123456789"},
		{"octal token", `printf '\147\150\160\137\141\102\063\144\105\065\147\110\067\152\113\071\155\116\061\160\121\162\123\164\125\166\127\170\131\172\060\061\062\063\064\065\066\067\070\071'`, "aB3dE5gH7jK9mN1pQrStUvWxYz0123456789"},
		{"\\xNN email", `echo -e 'mail bob\x40example.test now'`, "bob@example.test"},
		{"html json field", `{&quot;password&quot;: &quot;Vq7zLmQw2Xk9pR&quot;}`, "Vq7zLmQw2Xk9pR"},
		{"html numeric email", `write to qvortle&#64;example.test`, "qvortle@example.test"},
		{"double percent", `curl https://x.example.test/cb?q=password%253DVq7zLmQw2Xk9pR%2526a%253D1`, "Vq7zLmQw2Xk9pR"},
		{"fullwidth assignment", "ＴＯＫＥＮ＝Ｖｑ７ｚＬｍＱｗ２Ｘｋ９ｐＲ", "Ｖｑ７ｚＬｍＱｗ２Ｘｋ９ｐＲ"},
		{"fullwidth name", "thanks Ｖｏｒｂｅｌ　Ｔｒｉｎｑｕａｓ for it", "Ｔｒｉｎｑｕａｓ"},
		{"fullwidth email", "ｑｖｏｒｔｌｅ＠ｅｘａｍｐｌｅ．ｔｅｓｔ", "ｑｖｏｒｔｌｅ"},
	}
	for _, c := range cases {
		assertHidden(t, c.name, c.in, c.body, d)
	}
}

// A YAML line written inside a quoted string (`'  client_secret: "x"'`, a JSON string holding `password: x`) is
// still a credential's `name: value`: the quote that opens the string starts the line its receiver reads.
func TestAQuotedLineOpeningWithANameHidesItsValue(t *testing.T) {
	cases := []struct{ name, in, body string }{
		{"single-quoted yaml", `'  client_secret: "QQmyc97rNiCnj4"'`, "QQmyc97rNiCnj4"}, // gitleaks:allow (synthetic)
		{"double-quoted words", `"secret_key: brelkelyevskoq"`, "brelkelyevskoq"},
		{"escaped twice", `"\"password: beltorthijitq\""`, "beltorthijitq"},
		{"after a command", `echo "- db_password: f8n2IRVKyYZlJwk5"`, "f8n2IRVKyYZlJwk5"}, // gitleaks:allow (synthetic)
	}
	for _, c := range cases {
		assertHidden(t, c.name, c.in, c.body, NoDenylist)
	}
}

// A continuation is joined before any decoding: `%25` then `\` and a line break then `20` is `%2520`, a space
// read twice. Before, the joined reading was only one of two decodings, so the second percent level never came.
func TestAContinuationIsJoinedBeforeTheDecodings(t *testing.T) {
	d := fakeDenylist(t)
	cases := []struct{ name, in, body string }{
		{"sql", "make test\nCREATE%2520USER%2520app%2520IDENTIFIED%2520BY%2520\\\ndw_Hxware-nMACdp-sJHpmp_2tey%253B\necho done", "dw_Hxware-nMACdp-sJHpmp_2tey"},
		{"email", "make test\nthisab%252B\\\nnim%2540example.test\necho done", "nim@example.test"},
		{"name", "make test\nVorbel%2520Trin\\\nquas%2520said\necho done", "Trinquas"},
	}
	for _, c := range cases {
		assertHidden(t, c.name, c.in, c.body, d)
		if strings.Contains(Scrub(c.in, d, 100000), "nim%2540") {
			t.Errorf("%s: the encoded address survives", c.name)
		}
	}
}

// A cut output is at most limit runes (its marker included), scrubs to itself at the same limit, and passes the
// audit: it never ends on a name whose value the cut took (`apiKey: '<redacted>' …[cut]`, a fullwidth `＝`).
func TestACutOutputIsStableAndPassesTheAudit(t *testing.T) {
	cases := []struct {
		in    string
		limit int
	}{
		{`Thanks for the help "const cfg = { apiKey: 'MU71Qq10f_o7884cCB' };" with this one, it matters`, 61}, // gitleaks:allow (synthetic)
		{"pytest -q -x ｏｓ．ｅｎｖｉｒｏｎ［＂ＤＢ＿ＰＡＳＳＷＯＲＤ＂］　＝　＂ｓ－ｓ４ｔ２ａｆ－ｂｇ８ＴＧＣｎｒｎ＂ --maxfail 3 and more", 51},
		{"echo ａｕｔｈＴｏｋｅｎ　：＝　＂ｄＱ－ｇＲｆ２ｓＢＵＥ６ａＤＶ５－ＮｗＶ８Ｌ１Ｂ５３＂ the build is green", 26},
		{`tell me why it const%20cfg%20%3D%20%7B%20token%3A%20%272yo3T8Dg7alAgTgSY05JaAN2JA63gdtR%27%20%7D%3B fails then`, 52}, // gitleaks:allow (synthetic)
	}
	// The receiver (Python's audit) reads what follows `IDENTIFIED BY`, or a header's name and a placeholder, as a
	// value: the marker must not stand there.
	ends := []struct {
		in    string
		limit int
		tail  string
	}{
		{"echo ALTER USER 'app'@'%' IDENTIFIED BY 'A3-T45HU4-JSIOM1TMA7V-DI8FP-V5ASP-8RZHQMOE95B9E'; done", 47, "BY " + Cut},
		{`echo CREATE USER app WITH PASSWORD 'vanwenbelquingav7'; done`, 42, "PASSWORD " + Cut},
		{`tell me why it curl -s -H "Authorization: Bearer oN-kgtqJ0_bb" https://api.example.test/v1/me`, 48, "-H " + Cut}, // gitleaks:allow (synthetic)
		// A hidden value right after an empty assignment reads as more of it with the marker, and a flag awaits its value.
		{"say A_TOKEN= rk_prod_A6V4u4jwer1Rz7kQ9 and `--password hunter2xyz` then more words here", 20, "A_TOKEN= <redacted> " + Cut}, // gitleaks:allow (synthetic)
		{"say A_TOKEN= rk_prod_A6V4u4jwer1Rz7kQ9 and `--password hunter2xyz` then more words here", 30, "A_TOKEN= <redacted> " + Cut}, // gitleaks:allow (synthetic)
		{"say A_TOKEN= rk_prod_A6V4u4jwer1Rz7kQ9 and `--password hunter2xyz` then more words here", 20, "`--password " + Cut},         // gitleaks:allow (synthetic)
		{"say A_TOKEN= rk_prod_A6V4u4jwer1Rz7kQ9 and `--password hunter2xyz` then more words here", 30, "`--password " + Cut},         // gitleaks:allow (synthetic)
	}
	for _, c := range ends {
		for limit := c.limit; limit < c.limit+30; limit++ {
			if out := Scrub(c.in, NoDenylist, limit); strings.HasSuffix(out, c.tail) || strings.Contains(out, ":<redacted> "+Cut) {
				t.Errorf("%q ends on a name awaiting its value", out)
				break
			}
		}
	}
	// A cut drops words only for a hit the marker itself causes, never the whole text for one elsewhere.
	long := "x eyJhb.abcdefg.hijklmn y " + strings.Repeat("wo ", 2000)
	if out := Scrub(long, NoDenylist, 4000); len([]rune(out)) < 3000 {
		t.Errorf("the cut kept %d runes of a text that holds nothing", len([]rune(out)))
	}
	for _, c := range cases {
		out := Scrub(c.in, NoDenylist, c.limit)
		if n := len([]rune(out)); n > c.limit {
			t.Errorf("%q: %d runes, limit %d", out, n, c.limit)
		}
		if again := Scrub(out, NoDenylist, c.limit); again != out {
			t.Errorf("%q scrubs again to %q", out, again)
		}
		if hits := Audit(out, NoDenylist); len(hits) > 0 {
			t.Errorf("%q: audit %v", out, hits)
		}
	}
}

// Over-redaction found by measure (c) and the oracle's keep families: each output is the expected text exactly.
func TestKeptAroundAHiddenValue(t *testing.T) {
	cases := []struct{ name, in, want string }{
		// A quoted YAML line's value ends at the quote that closes the string, not at the shell word's end.
		{"quoted yaml line", `echo "password: fakeYamlPw23" >> config.yaml`, `echo "password: <redacted>" >> config.yaml`},
		// The oracle's keep family: what follows a credential's flag and reads as an option is no value.
		{"stdin dash", "tool --client-secret -", "tool --client-secret -"},
		{"short option", "tool --client-secret -v", "tool --client-secret -v"},
		{"option after a stdin flag", "docker login --password-stdin -u bob reg", "docker login --password-stdin -u bob reg"},
		// A password may still start with a dash.
		{"dash password", "tool --password -x9Kq2mZ7 next", "tool --password <redacted> next"},
		// A password-family flag takes even an option-like word as its value, as the receiver's audit reads it.
		{"password family takes --verbose", "tool --token --verbose", "tool --token <redacted>"},
		{"password family takes -v", "tool --password -v", "tool --password <redacted>"},
		{"password family takes --abc", "tool --secret --abc", "tool --secret <redacted>"},
		// `--name=value` after a credential flag is a value, not an option to leave.
		{"option-shaped value", "tool --client-secret --Abc=Zx81pLm0Qr", "tool --client-secret <redacted>"},
	}
	for _, c := range cases {
		if got := Scrub(c.in, NoDenylist, 4000); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if out := Scrub(c.in, NoDenylist, 4000); len(Audit(out, NoDenylist)) > 0 {
			t.Errorf("%s: the audit refuses %q: %v", c.name, out, Audit(out, NoDenylist))
		}
	}
}

// A continuation into a diff's `+` or `-` row joins the row's content, never its marker: read with the marker,
// the marker is a flag's value (`--password \` then `+    x`) and the audit refused a hidden row.
func TestAContinuationIntoADiffRowIsNotJoinedWithItsMarker(t *testing.T) {
	in := "diff --git a/run.sh b/run.sh\n--- a/run.sh\n+++ b/run.sh\n@@ -0,0 +1,2 @@\n+tool --password \\\n+    hunter2\n"
	out := ScrubDiff(in, NoDenylist, 4000)
	if strings.Contains(out, "hunter2") {
		t.Errorf("the value survives: %q", out)
	}
	if hits := Audit(out, NoDenylist); len(hits) > 0 {
		t.Errorf("the audit refuses %q: %v", out, hits)
	}
}

// `+` reads as a space with nothing percent-encoded too (a form body): `":_auth"+" "*n` is npm's `:_auth` and a
// value to the receiver. The decodings were made only when a `%` stood in the text, so this went out.
func TestAPlusReadsAsASpaceWithoutAPercent(t *testing.T) {
	in := ` "npm_auth": lambda n: ":_auth"+" "*n,`
	if out := Scrub(in, NoDenylist, 4000); !strings.Contains(out, "<redacted>") {
		t.Errorf("kept: %q", out)
	}
}

// Code's `name = value` whose value the scrubber hid in part (`<redacted>\[0\]` in a sed expression) is refused by
// the receiver's audit; this package's audit now reads it too, so the scrubber hides the rest of the value.
func TestASpacedAssignmentPartlyHiddenGoesWhole(t *testing.T) {
	in := `sed -i '' 's/auth_token = creds\[0\]\["token"\]/auth_token = creds[0].get("token")/' app.py`
	out := Scrub(in, NoDenylist, 4000)
	if strings.Contains(out, `<redacted>\[0\]`) {
		t.Errorf("a value partly sent: %q", out)
	}
	if hits := Audit(out, NoDenylist); len(hits) > 0 {
		t.Errorf("the audit refuses %q: %v", out, hits)
	}
	if hits := Audit(`auth_token = <redacted>[0]`, NoDenylist); len(hits) == 0 {
		t.Errorf("the audit passes a value partly sent")
	}
}

// A JWT glued to a word before it (`'^\{|word` then the token, in a grep pattern) is still a JWT: the scrubber's
// pattern wanted a word boundary, and the audit read no JWT at all.
func TestAGluedJWTIsHiddenAndAudited(t *testing.T) {
	jwt := "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiUGJzNXNnTko1In0.CmGfMBLfwlFhdpeC4U0yfMkG-iMp0hFqw12Ci9kEtr0" // gitleaks:allow (synthetic)
	assertHidden(t, "glued", `grep -E '^\{|line`+jwt+`' log.txt`, jwt, NoDenylist)
	if hits := Audit("token "+jwt, NoDenylist); len(hits) == 0 {
		t.Errorf("the audit passes a bare JWT")
	}
	if hits := Audit("x"+jwt, NoDenylist); len(hits) == 0 {
		t.Errorf("the audit passes a glued JWT")
	}
	// The audit's JWT reading needs as much as the scrubber's, so it refuses nothing the scrubber keeps.
	for _, in := range []string{"x eyJhb.abcdefg.hijklmn y", "xeyJabcdefg.0123456789.0123456789"} {
		if out := Scrub(in, NoDenylist, 4000); len(Audit(out, NoDenylist)) > 0 {
			t.Errorf("%q: the audit refuses what the scrubber keeps: %v", out, Audit(out, NoDenylist))
		}
	}
}

// A continuation into a line that starts with a dash that is not a diff row's marker (`"@handle\` then `-ops"`)
// joins as the shell joins it, dash and all.
func TestAContinuationBeforeADashJoinsIt(t *testing.T) {
	d, err := ParseDenylist([]byte(`{"identities": [{"regex": "plivek[0-9]{3}-ops", "role": "person"}], "vendors": []}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	assertHidden(t, "regex handle", "x\n\"@plivek863\\\n-ops\"\ny", "plivek863", d)
}

// A diff quoting a diff: a context row ` +@pytest.mark.x` reads as an address to the receiver (Python's audit and
// this package's read the rows as written), though on its side the row starts with it. ScrubDiff read only sides.
func TestAnAddressShapeInAQuotedDiffRowIsHidden(t *testing.T) {
	in := "--- a/n.txt\n+++ b/n.txt\n@@ -1,3 +1,4 @@\n see below\n+x\n +@pytest.mark.parametrize(\"a\", [1])\n +def test_a(a): pass\n"
	out := ScrubDiff(in, NoDenylist, 4000)
	if hits := Audit(out, NoDenylist); len(hits) > 0 {
		t.Errorf("the audit refuses %q: %v", out, hits)
	}
}

// A vendor token attached to a one-letter option (`curl -d` then the token, `mysql -p` then one): the token's
// prefix has no word boundary before it, so the format table never matched it.
func TestATokenAttachedToAShortOptionIsHidden(t *testing.T) {
	tok := "shippo_live_MqWpLQsoXs5kSZIT9"
	assertHidden(t, "attached", `x "curl -d`+tok+` \"a=9\" a"`, tok, NoDenylist)
	if hits := Audit("curl -d"+tok, NoDenylist); len(hits) == 0 {
		t.Errorf("the audit passes an attached token")
	}
}

// A Markdown rule (`--- ` line) does not make a prompt a diff: a continuation before a dash still joins, so a
// phone split there is read whole.
func TestAMarkdownRuleIsNoDiff(t *testing.T) {
	assertHidden(t, "phone", "notes\n--- intro\n\"(801) 555\\\n-0124\"\nend", "(801) 555", NoDenylist)
}

// A tuple's hidden item (`_KEY = (<redacted>, 2, 3)`) is no value partly sent: the spaced-assignment reading must
// not take the opening bracket into the value, or the receiver reads `<redacted> 2` as one.
func TestATupleItemIsNotAValuePartlySent(t *testing.T) {
	if out := Scrub("_KEY = (1, 2, 3, 4, 5, 6)\n", NoDenylist, 4000); out != "_KEY = (<redacted>, 2, 3, 4, 5, 6)\n" {
		t.Errorf("%q", out)
	}
}

// curl's user options take a password after the user's colon: `-U` glued (`-Uuser:pass`, as `-uuser:pass`), and
// after other short options combined (`-kuuser:pass`, `-kUuser:pass`), where the `u`/`U` takes the rest of the word.
// Each was a command Go's own audit refused.
func TestACurlUserOptionHidesItsPassword(t *testing.T) {
	assertHidden(t, "proxy user glued", `"curl -Udeploye:passwo9rdabcd https://x",`, "passwo9rdabcd", NoDenylist)
	assertHidden(t, "user after combined flags", `"curl -kuoperatr:passwo9rdabcd https://x",`, "passwo9rdabcd", NoDenylist)
	assertHidden(t, "proxy user after combined flags", "curl -kUadmin:pw98765xyz http://x", "pw98765xyz", NoDenylist)
}

// A quoted value on the line after an empty `NAME=` is that name's value to the receiver (Python's audit): it goes
// whole, never as `"echo <redacted>"`.
func TestAQuotedValueAfterAnEmptyAssignmentGoesWhole(t *testing.T) {
	out := Scrub("X=1 GH_AUTH_TOKEN=\n\"echo rk_prod_A6V4u4jwer1Rz7k\"\nnext", NoDenylist, 4000) // gitleaks:allow (synthetic)
	if strings.Contains(out, "\"echo <redacted>\"") {
		t.Errorf("a quoted value after an empty assignment, partly sent: %q", out)
	}
}

// An unquoted header's hidden value with punctuation glued to it (`-H X-Token:<redacted>,`) is read by the receiver
// (Python's audit) as a value partly sent; this package's audit now reads it too.
func TestAnUnquotedHeaderValueWithAGluedCommaIsRefused(t *testing.T) {
	if hits := Audit(`curl -H X-Token:<redacted>, more`, NoDenylist); len(hits) == 0 {
		t.Errorf("the audit passes it")
	}
	if hits := Audit(`curl -H X-Token:<redacted> more`, NoDenylist); len(hits) > 0 {
		t.Errorf("the audit refuses a hidden value alone: %v", hits)
	}
}

// `--user-agent 'a:b'` is no `--user`: the audit read the agent string's colon as a password the scrubber kept.
func TestAUserAgentIsNoUser(t *testing.T) {
	if hits := Audit(`"curl --user-agent 'a:b' x",`, NoDenylist); len(hits) > 0 {
		t.Errorf("the audit refuses a user agent: %v", hits)
	}
}

// An empty YAML block scalar (`password: >-` then a sibling key at the same indentation) holds nothing: the audit
// read the next key as the block's body, which the scrubber, reading YAML's indentation, rightly kept.
func TestAnEmptyBlockScalarHoldsNoValue(t *testing.T) {
	in := "config:\n  password: >-\n  storage_key: |\n    plain words\n"
	if hits := Audit(Scrub(in, NoDenylist, 4000), NoDenylist); len(hits) > 0 {
		t.Errorf("the audit refuses %q: %v", Scrub(in, NoDenylist, 4000), hits)
	}
}

// A credential's value that opens with a code word or a type word glued by punctuation to more of it
// (`Fn-DMLYtO2`, `True@Lm9Qx2`, `None-q7Xb2Kd`) is a value, not `fn`, `true` or a `None` annotation: the scrubber kept
// it after `=` and `:`, and the audit passed the `@` and `: None-` ones. A code word with an operator or a bracket
// after it stays code.
func TestACodeWordGluedToAValueIsTheValue(t *testing.T) {
	d := fakeDenylist(t)
	cases := []struct{ name, in, body string }{
		{"lead word, hyphen, mid-sentence", "then db_password = Fn-DMLYtO2 for the call", "Fn-DMLYtO2"},    // gitleaks:allow (synthetic)
		{"fullwidth, after a command", "echo start ｔｈｅｎ　ｄｂ＿ｐａｓｓｗｏｒｄ　＝　Ｆｎ－ＤＭＬＹｔＯ２　ｆｏｒ　ｔｈｅ　ｃａｌｌ", "ＤＭＬＹｔＯ２"}, // gitleaks:allow (synthetic)
		{"keyword, at sign, colon", "Then db_password: True@Lm9Qx2 and continue", "True@Lm9Qx2"},           // gitleaks:allow (synthetic)
		{"type word, hyphen, colon", "db_password: None-q7Xb2Kd", "None-q7Xb2Kd"},                          // gitleaks:allow (synthetic)
	}
	for _, c := range cases {
		assertHidden(t, c.name, c.in, c.body, d)
	}
	for _, in := range []string{"token = this->token;", "token = await fetchToken(url)", "token: str|None = None",
		"type A = {token:string;user:string;}", "password = null;next = 1",
		"s/^PER_TOKEN = None/OLD_LIMIT/g"} {
		if out := Scrub(in, d, 4000); out != in {
			t.Errorf("Scrub(%q) = %q, want it kept", in, out)
		}
	}
}

// A credential's colon value that no colon rule read, so it was sent and the net passed it: glued to the colon at a
// line's head, after a dotted owner, after `( `, opening with a `$` that is no reference, after a quote that never
// closes, and mid-sentence with `@` `#` `,` inside it; and a dotted value after `:` or `=` that was read as a member
// chain though a part of it mixes cases and a digit; and a crypt hash whose parameters hold commas, which the value
// stopped at, or whose hyphenated head (`$bcrypt-sha256$`) read as a reference. Each is hidden, and the audit refuses it
// unscrubbed.
func TestAColonValueOutsideTheColonRulesIsHiddenAndRefused(t *testing.T) {
	d := fakeDenylist(t)
	cases := []struct{ name, in, body string }{
		// A hash or password behind a scheme tag (`{CRYPT}`, `{SSHA}`), which the value stopped at, and LDIF's base64
		// value after `::`.
		{"scheme tag, line's head", "password: {CRYPT}$6$rounds=5000$saltsalt$Qz7Kp2Lm9Xa8Bc7De6",
			"Qz7Kp2Lm9Xa8Bc7De6"}, // gitleaks:allow (synthetic)
		{"scheme tag mid-sentence", "Then password: {ARGON2}$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd ok",
			"Kq9Lm2Pw7Xc4zzAbCd"}, // gitleaks:allow (synthetic)
		{"scheme tag, code assignment", "password = {SSHA}Zm9vYmFyYmF6cXV4c2FsdA9Kp3Lm",
			"Zm9vYmFyYmF6cXV4c2FsdA9Kp3Lm"}, // gitleaks:allow (synthetic)
		{"scheme tag, `#` opens the password, `:=`", "password := {PLAIN}#Ab12cd34", "Ab12cd34"}, // gitleaks:allow (synthetic)
		{"LDIF base64 after `::`", "userPassword:: e1BMQUlOfUh1bnRlcjJLcTlMbQ==",
			"e1BMQUlOfUh1bnRlcjJLcTlMbQ"}, // gitleaks:allow (synthetic)
		{"glued at a line's head", "password:Ab12cd34x", "Ab12cd34x"},                             // gitleaks:allow (synthetic)
		{"dotted owner at a line's head", "spring.datasource.password: Ab-CDEFgH2", "Ab-CDEFgH2"}, // gitleaks:allow (synthetic)
		{"dotted owner after a comma", "Okay, db.password: Ab-CDEFgH2 then", "Ab-CDEFgH2"},        // gitleaks:allow (synthetic)
		{"bcrypt hash mid-sentence", "Then password: $2b$12$Kq9Lm2Pw7Xc4 ok", "Kq9Lm2Pw7Xc4"},     // gitleaks:allow (synthetic)
		{"unclosed quote mid-sentence", `Then password: "Ab-CDEFgH2 and continue`, "Ab-CDEFgH2"},  // gitleaks:allow (synthetic)
		{"blank before the colon", "Then password : Ab@CDEFgH2 and continue", "CDEFgH2"},          // gitleaks:allow (synthetic)
		{"hash inside, mid-sentence", "Then password: Ab#CDEFgH2 and continue", "CDEFgH2"},        // gitleaks:allow (synthetic)
		{"dotted, glued at a line's head", "password:Ab.CDEFgH2", "CDEFgH2"},                      // gitleaks:allow (synthetic)
		{"dotted, mid-sentence", "Then password: Ab.CDEFgH2 and continue", "CDEFgH2"},             // gitleaks:allow (synthetic)
		{"dotted, code assignment", "token = x9.Kq2Lm.Pw7", "Kq2Lm"},                              // gitleaks:allow (synthetic)
		// A dotted value with a bracket after a blank, read as a call, and a `#` glued to a crypt head or a scheme tag,
		// read as a comment.
		{"dotted, a bracket after a blank, `=`", "password = Ab.CDEFgH2 (rotated)", "CDEFgH2"},   // gitleaks:allow (synthetic)
		{"dotted, a bracket after a blank, `:=`", "password := Ab.CDEFgH2 (rotated)", "CDEFgH2"}, // gitleaks:allow (synthetic)
		{"`#` before a crypt head, `:=`", "password := ab#$scrypt$ln=16,r=8$c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd",
			"c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd"}, // gitleaks:allow (synthetic)
		{"`#` opens a crypt hash", "password = #$scrypt$ln=16,r=8$c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd",
			"c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd"}, // gitleaks:allow (synthetic)
		{"`#` opens a scheme tag", "password = #{CRYPT}$6$rounds=5000,x$c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd",
			"c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd"}, // gitleaks:allow (synthetic)
		{"crypt hash with commas, `:=`", "password := $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd",
			"Kq9Lm2Pw7Xc4zzAbCd"}, // gitleaks:allow (synthetic)
		{"Django's argon2 hash, `=>`", "password => argon2$argon2id$v=19$m=102400,t=2,p=8$Rk9PYmFy$Zx8Wv7Ut6Sr5Qp4On3Ml",
			"Zx8Wv7Ut6Sr5Qp4On3Ml"}, // gitleaks:allow (synthetic)
		{"hyphenated crypt hash mid-sentence", "Then password: $bcrypt-sha256$v=2,t=2b,r=12$n79VH.0Q2TMWmt3Oqt9uku$Kq4Noyk3094Y2QlB8NdRT8SvGiI4ft2 and go",
			"Kq4Noyk3094Y2QlB8NdRT8SvGiI4ft2"}, // gitleaks:allow (synthetic)
		// A bare value after a credential's quoted name and its colon (a dict or a YAML key in quotes), and a scheme tag
		// after other characters of its word, which the code word stopped at.
		{"quoted name, dotted value", "'password': Ab.CDEFgH2", "CDEFgH2"},                                  // gitleaks:allow (synthetic)
		{"quoted name, a value opening with the name", `{"password": password-hunter2}`, "hunter2"},         // gitleaks:allow (synthetic)
		{"quoted name, a note after a blank", `"password": Ab.CDEFgH2 (rotated)`, "CDEFgH2"},                // gitleaks:allow (synthetic)
		{"quoted name in an object literal", `x = {"api_key": Kq9Lm2Pw7Xc, "region": "us"}`, "Kq9Lm2Pw7Xc"}, // gitleaks:allow (synthetic)
		{"scheme tag after a prefix, `:=`", "password := y{SSHA}Zm9vYmFyYmF6cXV4c2FsdA9Kp3Lm",
			"Zm9vYmFyYmF6cXV4c2FsdA9Kp3Lm"}, // gitleaks:allow (synthetic)
		{"scheme tag after a prefix, quoted name", `"password": x#y{SSHA}Zm9vYmFyYmF6cXV4c2FsdA9Kp3Lm`,
			"Zm9vYmFyYmF6cXV4c2FsdA9Kp3Lm"}, // gitleaks:allow (synthetic)
		// A password hash its own format names, with no credential's name before it.
		{"crypt hash in a sentence", "the hash is $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$Kq9Lm2Pw7Xc4zzAbCd",
			"Kq9Lm2Pw7Xc4zzAbCd"}, // gitleaks:allow (synthetic)
		{"md5-crypt hash in a CSV row", "admin,$1$abc12345$Qz7Kp2Lm9Xa8Bc7De6Fg5H,x", "Qz7Kp2Lm9Xa8"}, // gitleaks:allow (synthetic)
		{"scheme tag in a sentence", "stored {SSHA}Zm9vYmFyYmF6cXV4c2FsdA9Kp3Lm in the row",
			"Zm9vYmFyYmF6cXV4c2FsdA9Kp3Lm"}, // gitleaks:allow (synthetic)
		// A plain password's short value behind its tag, and a type word followed by what no type syntax writes.
		{"short plain value behind its tag", "stored {PLAIN}pw in the row", "{PLAIN}pw"},
		{"type word, a member", "password: str.x9KqLm2Pw", "x9KqLm2Pw"}, // gitleaks:allow (synthetic)
		{"type word, a union of a value", `{"password": string|hunter2pw, "user": "bob"}`, "hunter2pw"},
		{"type word, arguments no type writes", "password: Optional[x9KqLm2Pw]", "x9KqLm2Pw"},
		// A literal after a type word that goes on as code, after an unquoted, a quoted or a parenthesised name.
		{"type word, a ternary", `{password: undefined ? fallback : "Kq9Lm2Pw7Xc"}`, "Kq9Lm2Pw7Xc"},        // gitleaks:allow (synthetic)
		{"type word, an index", `{password: string[0] ?? "Kq9Lm2Pw7Xc"}`, "Kq9Lm2Pw7Xc"},                   // gitleaks:allow (synthetic)
		{"type word, a union", `{password: undefined | "Kq9Lm2Pw7Xc"}`, "Kq9Lm2Pw7Xc"},                     // gitleaks:allow (synthetic)
		{"type word, a member, ??", `{password: String.raw ?? "Kq9Lm2Pw7Xc"}`, "Kq9Lm2Pw7Xc"},              // gitleaks:allow (synthetic)
		{"quoted name, type word, ??", `{"password": str ?? "Kq9Lm2Pw7Xc", "user": "bob"}`, "Kq9Lm2Pw7Xc"}, // gitleaks:allow (synthetic)
		{"after `(`, type word, ??", `f(user, secret: None ?? "Kq9Lm2Pw7Xc")`, "Kq9Lm2Pw7Xc"},              // gitleaks:allow (synthetic)
		// A triple quote whose body opens with its quote character.
		{"triple quote, body opens with its quote", "{password: str or ````, a```` + \"Kq9Lm2Pw7Xc\"}", "Kq9Lm2Pw7Xc"}, // gitleaks:allow (synthetic)
		// A run of backticks the value's end read as a triple quote and the audit one at a time.
		{"four backticks, then a triple", "{password: str or ````, a``` + \"Kq9Lm2Pw7Xc\"}", "Kq9Lm2Pw7Xc"}, // gitleaks:allow (synthetic)
		// A keyword argument (a call, a lambda, a word an operator follows): the named rule took its first word, sent the rest.
		{"keyword argument, a call's default", `f(password=os.environ.get("PW", "Kq9Lm2Pw7Xc"))`, "Kq9Lm2Pw7Xc"},           // gitleaks:allow (synthetic)
		{"keyword argument, the call on the next line", "f(token=\n    os.getenv(\"T\", \"Kq9Lm2Pw7Xc\"))", "Kq9Lm2Pw7Xc"}, // gitleaks:allow (synthetic)
		{"keyword argument, a lambda", `f(token=lambda a, b: "Kq9Lm2Pw7Xc")`, "Kq9Lm2Pw7Xc"},                               // gitleaks:allow (synthetic)
		{"keyword argument, a lambda's default", `f(token=lambda a=lambda: 0, b=1: 'Kq9Lm2Pw7Xc')`, "Kq9Lm2Pw7Xc"},         // gitleaks:allow (synthetic)
		{"keyword argument, a fallback after a word", `f(user, password=pw or "Kq9Lm2Pw7Xc")`, "Kq9Lm2Pw7Xc"},              // gitleaks:allow (synthetic)
		// A literal on the line after a lone word: the word was taken as the whole value.
		{"a lone word, a literal on the next line", "password: foo\n\"Kq9Lm2Pw7Xc\"", "Kq9Lm2Pw7Xc"},                     // gitleaks:allow (synthetic)
		{"quoted name, a literal on the next line", "{\"password\": foo\n \"Kq9Lm2Pw7Xc\"}", "Kq9Lm2Pw7Xc"},              // gitleaks:allow (synthetic)
		{"a lone word, a prefixed literal on the next line", "password: foo\nf\"Kq9Lm2Pw7Xc\"", "Kq9Lm2Pw7Xc"},           // gitleaks:allow (synthetic)
		{"a lone word, a literal after a form feed on the next line", "password: foo\n\f\"Kq9Lm2Pw7Xc\"", "Kq9Lm2Pw7Xc"}, // gitleaks:allow (synthetic)
		// A literal after a `;` in the value: the `;` ended it.
		{"quoted name, a literal after a `;`", `{"password": str;"Kq9Lm2Pw7Xc"}`, "Kq9Lm2Pw7Xc"}, // gitleaks:allow (synthetic)
		{"a word, a literal after a `;`", `{password: str;"Kq9Lm2Pw7Xc"}`, "Kq9Lm2Pw7Xc"},        // gitleaks:allow (synthetic)
	}
	for _, c := range cases {
		assertHidden(t, c.name, c.in, c.body, d)
		if hits := Audit(c.in, d); len(hits) == 0 {
			t.Errorf("%s: Audit(%q) passes it unscrubbed", c.name, c.in)
		}
	}
	for _, in := range []string{"Then password: $DB_PASSWORD2 and continue", "see http://example.com:8080/a",
		"Then token::Token2x here", "at 10:30 today", "token = conf.api_key2", "password:conf.api_key2",
		"'password': conf.api_key2", `"password": getpass.getpass()`, "echo $HOME$PATH", "price is $5$ and $10$"} {
		if out := Scrub(in, d, 4000); out != in {
			t.Errorf("Scrub(%q) = %q, want it kept", in, out)
		}
	}
}

// A denylisted name whose words are joined by any dash (a Unicode hyphen, an en or em dash, the minus sign) or an
// invisible format character (a soft hyphen, a zero-width space), or a hyphenated name written with another joiner,
// is hidden whole, and the audit refuses it unscrubbed.
func TestANameJoinedByAnyDashIsHiddenAndRefused(t *testing.T) {
	d := fakeDenylist(t)
	cases := []struct{ name, in, body string }{
		{"hyphen U+2010", "ping Vorbel\u2010Trinquas about it", "Vorbel\u2010Trinquas"},
		{"non-breaking hyphen U+2011", "ping Vorbel\u2011Trinquas about it", "Vorbel\u2011Trinquas"},
		{"en dash U+2013", "Zo\u00eb\u2013Quillfen reviewed it", "Zo\u00eb\u2013Quillfen"},
		{"spaced em dash U+2014", "thanks Vorbel \u2014 Trinquas", "Vorbel \u2014 Trinquas"},
		{"minus sign U+2212", "ping Vorbel\u2212Trinquas", "Vorbel\u2212Trinquas"},
		{"soft hyphen U+00AD", "ping Vorbel\u00adTrinquas", "Vorbel\u00adTrinquas"},
		{"zero-width space U+200B", "ping Vorbel\u200bTrinquas", "Vorbel\u200bTrinquas"},
	}
	for _, c := range cases {
		assertHidden(t, c.name, c.in, c.body, d)
		if hits := Audit(c.in, d); len(hits) == 0 {
			t.Errorf("%s: Audit(%q) passes it unscrubbed", c.name, c.in)
		}
	}
	hy, err := ParseDenylist([]byte(`{"identities": [{"literal": "Marijo-Tavel Plenkor", "role": "person"}], "vendors": []}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"by Marijo\u2013Tavel Plenkor", "by Marijo Tavel Plenkor", "by MarijoTavel Plenkor"} {
		assertHidden(t, "hyphenated literal: "+in, in, strings.TrimPrefix(in, "by "), hy)
	}
}
