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
