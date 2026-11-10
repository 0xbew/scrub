# scrub

scrub removes secrets and identities from text before the text leaves a machine, then audits its own
output and refuses to send when anything still looks sensitive. It is a Go library and a small CLI,
standard library only.

It was built for developer tooling that sends shell commands, prompts, diffs and logs to a model or to
shared storage. Hiding too much is a cost, but sending a leak is the failure it exists to prevent, so
when in doubt it refuses.

```go
import "github.com/0xbew/scrub"

d, err := scrub.LoadDenylist(path) // names, handles and vendors to hide; see "The denylist"
if err != nil {
	return err // a configured list that cannot be used means nothing is sent
}
out := scrub.Scrub(text, d, 4000)         // at most 4000 runes, everything sensitive replaced
if hits := scrub.Audit(out, d); len(hits) > 0 {
	return refuse(hits) // rule ids only, never the text
}
send(out)
```

## What it guarantees

These are the rules it is built and measured against.

**Never sent**

1. **A credential's value**, after a credential's name, written as a shell flag (`--token X`, `--token=X`,
   `-pX`), an environment assignment, a JSON field, a header or auth scheme (`Authorization: Bearer X`,
   cookies), a code literal (Python, JS, Go, YAML, SQL), URL userinfo or a query parameter, or a program
   option such as `mysql -p`. The whole value goes, never a part of it.
2. **A known vendor token format or a JWT**, named or not, and any run of 32 or more token characters that
   holds both a letter and a digit. The exceptions are a path and an identifier written as code.
3. **An identity on the denylist** (a name, handle or vendor), **an email address or a phone number**.
4. **In any reading a receiver may apply.** Rules 1 to 3 hold for the text as written, each level of
   backslash unescaping, as a JSON string (including `\u` escapes past ASCII and surrogate pairs), `\xNN`
   and octal escapes, percent-decoded once and twice, HTML entities, fullwidth letters folded to ASCII,
   shell line continuations joined, and each side of a unified diff.

**Kept readable**

5. Text with nothing sensitive is meant to come back unchanged (the gate caps changes at 0.1% of clean real
   texts). Credential names, flags, scheme words, program names,
   paths, identifiers, dates, versions and ids stay. Each placeholder says what it hid (`<redacted>`,
   `<long-token>`, `<redacted-jwt>`, `[email]`, `[phone]`, `[owner]`, `[teammate]`, `[person]`, `[vendor]`),
   and `ScrubDiff` keeps every row and marker.
6. Scrubbing is stable: scrubbing an output again changes nothing, and a length cut never ends inside a
   secret (`…[cut]` marks it, within the limit).

**Refuse when unsure**

7. `Audit` and `AuditBody` read the exact bytes about to be sent, decoded the way the receiver will decode
   them. Any hit should refuse the whole send. They return rule ids, never text.
8. A denylist that is configured but missing, unreadable or invalid is an error, and one invalid entry
   rejects the whole list; the CLI then answers no request. Output still changing after a bounded number
   of re-reads is cut rather than sent.
9. The audit's checks are separate code from the scrubber's detectors (its safety net, `internal/auditnet`, which imports nothing from the detectors), so one
   bug in a detector does not also blind the audit. See "Known gap" for what it cannot see.

## Known gap

Measured by turning each scrubber detector off in turn (6,131 canaries), the audit still refuses all but 10 of
the leaked canaries, and with every detector off at once all but 9 of 5,077:

- shape fragments a length cut leaves (a phone number or a two-word name split just before `…[cut]`): the
  detector sees the whole shape past the limit, the audit only the fragment;
- a few encoded forms where another rule took part of an escape or a glued token's prefix (one named value,
  one code literal, four vendor tokens);
- with every detector off at once, a letters-only token after `Bearer`.

The audit's own checks are also narrower than the scrubber in places the scrubber still covers: mysql options
after a positional argument or a quoted `-e`, and a capitalised letters-only value read as a type name.

## Errs toward hiding

After a strong credential name (one whose last word is the credential itself: `password`, `secret`, `token`,
`api_key`, `DB_PASSWORD`), any plain word of three or more letters is hidden, even mid-sentence and even when
it is prose or code: `see password: letmein here` sends `see password: <redacted> here`, and so do
`Invalid password: authentication failed` (`authentication` goes) and `password = getpass (prompt)`.
`Audit` refuses such a text as written.

## What it does not do

These are left out on purpose. They are kept as written:

- **Base64 or gzip payloads.** Only the 32-character long-run rule covers them.
- **Look-alike letters** other than fullwidth forms (a Cyrillic `о` in a name).
- **Phone numbers written percent-encoded.** Reading `+` as a space there would hide diff rows.
- **A value whose name is not a credential's and that does not look random** (`n: hunter2`), prose that
  names a credential and then a short word (`the token is abc`), a cookie on the line after an empty pair,
  and a second word after a Bearer token (`Authorization: Bearer abc def`).
- **Anything not in the token catalogue or the denylist that does not look random**, such as a short
  password with no name before it.
- **Mid-sentence, after a weaker credential name** (`auth`, `dsn`, `otp`, `pat`), a letters-only word under 13
  letters (`see auth: rotated here`). After a strong name, a word of one or two letters, and a verb a commit
  message puts there (`Fix token: refresh it`).
- **A vendor token glued to a word before it** (`xsk-…`), except formats whose prefix is distinctive
  enough to read glued (`prod_AKIA…`, `x_sk_live_…`, `a3xoxb-…`, `checkedglpat-…`). Those err toward hiding: a
  word that ends in such a prefix and runs on in the token's alphabet (`WORLDWIDEAKIA…`) is hidden from the prefix.

It is a filter for text you are about to send, not a secret scanner for repositories: use a scanner such
as gitleaks for that. It does not make sending safe on its own; send only what passes `Audit`.

## API

| | |
|---|---|
| `Scrub(text, d, limit) string` | secrets, addresses, phones and the denylist's names removed; at most `limit` runes |
| `ScrubDiff(text, d, limit) string` | `Scrub` for a unified diff: each hunk side read as its file holds it, every row kept |
| `Redact(text, limit) string` | secrets only (no addresses, phones or names) |
| `Audit(text, d) []Hit` | rule ids that fire anywhere in `text`; empty means it may be sent |
| `AuditBody(body, d) []Hit` | `Audit` over a JSON document or JSON lines, as the receiver decodes them; undecodable is `unreadable` |
| `AuditValue(v, d) []Hit` | `Audit` over every string (keys included) in a decoded JSON value |
| `LoadDenylist(path)` / `ParseDenylist(payload, version)` | the denylist, or a `*DenylistError` whose message never quotes an entry or a path |
| `NoDenylist` | an explicit choice to scrub without a denylist (secrets and shapes only); a nil denylist sends nothing |

## The denylist

A JSON object with a whole-number `version` of 1 or more, `identities` and `vendors`:

```json
{
  "version": 1,
  "identities": [
    {"literal": "Ada Example", "role": "owner"},
    {"regex": "build-bot-[0-9]{3}", "role": "person"}
  ],
  "vendors": ["Examplecorp"]
}
```

`role` is `owner`, `teammate` or `person`, and names the placeholder. A literal matches case-insensitively,
with any run of spaces, `.`, `_` or `-` (or none) between its words, and never inside a longer word. Unknown keys, an empty
list of identities, a regex that does not compile, a pattern that matches empty text or a placeholder, and
a vendor shorter than three characters are all errors.

## CLI

```
go install github.com/0xbew/scrub/cmd/scrub@latest
scrub [--denylist PATH] < requests.jsonl
```

One JSON request per line, `{"op": "scrub"|"scrub_diff"|"redact"|"audit_text"|"audit_body", "text": "...", "limit": 4000}`,
and one answer per line: `{"out": "..."}` or `{"hits": [...]}`. A denylist that cannot be used is a single
line `{"denylist_error": "..."}`, and no request is answered.

## How it is checked

`go test ./...` runs the unit tests. Releases are also measured by a conformance gate run on real text that
stays on the maintainer's machine, so it is not part of this repository: synthetic canaries (random tokens,
every vendor prefix, JWTs, fake names, addresses at reserved test domains, phones in fictional ranges) are
planted one per real text in every shape, position and encoding above, and none may survive in any reading of
the output; both audits must pass every output; the share of clean texts changed is capped; an unusable
denylist must send nothing; and output that will not settle must come out cut. Rule 9 is measured by turning
each scrubber detector off in turn and checking the audit still refuses what leaks, except the fragments listed
under "Known gap".

## Design

[DESIGN.md](DESIGN.md) covers the readings, the lexer, each detector, rendering, diffs and the audit.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). `internal/tokens/tokens.json` is generated from the
[gitleaks](https://github.com/gitleaks/gitleaks) rule catalogue (MIT).
