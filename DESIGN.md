# scrub: design

One scrubber and one pre-send audit for every sender: a local recorder and a prompt
classifier use the library, a review bot uses the `scrub` CLI. Standard library only. An
earlier Python scrubber (frozen at v22) is the regression check; this package is a clean
design that must keep at least what Python hides, never a pattern port.

## Why not a port

Python v22 restates 8 root rules as 77 regex passes plus 44 audit patterns, most of them
one rule re-spelled for a quoting, an escape level, an encoding or a diff continuation.
Go's `regexp` is RE2 (no lookarounds), so a port is impossible, and it would carry the
stapling over. Here each root rule is written once, as Go code, and the quoting,
escaping and encoding are handled once, by the readings.

## Layout

The module root holds the public API only (`Scrub`, `ScrubDiff`, `Redact`, `Audit`, `AuditBody`,
`AuditValue`, the denylist and the classifiers); everything behind it is under `internal/`:

| package | holds |
|---|---|
| `internal/lex` | the lexer's extents, character classes, placeholders, diff rows |
| `internal/reading` | readings and their offset maps |
| `internal/vocab` | the classifiers |
| `internal/tokens` | vendor token formats (`tokens.json`) |
| `internal/span`, `internal/gate` | hidden spans; the gate build's detector switches |
| `internal/denylist` | the compiled identity and vendor list |
| `internal/detect` | the detectors, one file per family, and their registry |
| `internal/audit` | the pre-send audit |
| `internal/auditnet` | the audit's safety net; it imports nothing from `internal/detect` (rule 9) |
| `internal/engine` | the pipeline: readings, detectors, render, re-read, cut, diffs |

## Pipeline

```
text -> cut to limit+margin -> readings -> detectors -> hidden spans (source offsets)
     -> union -> render once -> cut to limit
```

### 1. Readings (`internal/reading`)

A reading is a decoded view of the source with an offset map: every byte of the reading
knows the source span it came from. The scrubber and the audit read the same set, the
set the receiver may apply:

| reading | how |
|---|---|
| raw | as written |
| unescaped xN | each level removes one backslash before any character (`\x` -> `x`), up to 8 levels, until it holds still |
| JSON string, at each level | the level read as a string's escapes: `\n` `\r` `\t` are line breaks and tabs, `\uXXXX` its character (past ASCII too, a surrogate pair as one), `\xNN` and octal `\NNN` their byte; only when the level holds one, and not read further down |
| continuations joined | `\` then a line break read as nothing, as a shell joins the lines (not into a diff's `+` or `-` row); made first, so the decodings below read an escape a continuation split |
| percent-decoded | `%XX` -> byte with `+` kept, and again with `+` -> space (a form body: also when no `%` stands) |
| HTML entities | `&quot;` and the other named entities that stand for punctuation, `&#NN;`, `&#xHH;` |
| fullwidth folded | U+FF01..U+FF5E -> ASCII, the ideographic space -> a space |
| two decodings in turn | any two of the four above, so `%2522` reads `"` and `&amp;quot;` reads `"` |
| each of these, then unescaped xN (and JSON) | both |
| diff sides (scrub_diff only) | new side (context + added rows), old side (context + removed rows), markers stripped |

Two facts every reading carries, because a decoded byte can stand for more than itself:

- **Its source form.** A quoted value ends at a quote written as its opener: `%22abc"Vq7%22`
  read percent-decoded is `"abc"Vq7"`, and the raw `"` is the value's, not its end
  (`reading.sameForm`, `quotedEnd`). A line break written escaped (`\` then the break) inside
  a quoted value is a continuation, so the value reads on past it (`contBreak`).
- **Whether it is joined.** Read as a plain escape, `\n` is the letter `n`, gluing the words
  either side of it. Such a reading is marked `joined`; shapes, JWTs, long runs and the
  denylist skip it (its JSON twin reads them apart), so a glued `abc\ndef...` cannot invent a
  long run.

A detector finds a value in a reading; the value's reading span maps back to a source
span, and that source span is hidden. So one JSON-field rule covers `"k": "v"`,
`\"k\": \"v\"`, `\\\"k\\\"...` and `%22k%22%3A%22v%22`, where Python needed a pass for
each. Mapping back can only widen what is hidden (an escape's backslash goes with its
character), never narrow it.

### 2. The lexer (`internal/lex`)

One set of extent functions, used by every detector, so "where a value ends" is decided
in one place:

- `wordEnd`: a shell word. Bare characters up to unescaped whitespace; `\ ` and `\<newline>`
  continue it; double-quoted parts honour backslash escapes and may span lines when they
  close, else run to the line end; single-quoted parts have no escapes, same closing rule;
  parts glue (`"ab"cd'ef'`).
- `literalEnd`: a code string literal (prefixes `r b u f E N`, triple quotes, backticks,
  escaped quotes one level down), the statement end (`statementEnd`: open brackets,
  trailing operators, leading operators on the next line, up to 12 lines).
- `quotedRegion`: the shell-quoted word enclosing a position, read left to right per line.
- `commandOf`: a command's extent for argv detectors, to an unquoted `|` `;` `&` or the
  line end, continuations joined.
- `objectEnd` (braces with strings skipped), `heredocBody`, `blockScalarBody` (YAML
  indentation), `sqlLiteral`.
- **Placeholders are atomic**: a value that is entirely placeholders (and quotes) is
  already hidden, so the detectors never re-read their own output. Idempotence
  (`Scrub(Scrub(x)) == Scrub(x)`) follows from this; there is no fixed-point loop.

### 3. The root rules as Go types (`internal/detect`, `internal/vocab`)

```go
type Kind uint8              // what a hidden span becomes: secret, long, jwt, email, phone, owner, teammate, person, vendor
type Span struct{ Lo, Hi int; Kind Kind }

type Detector struct{ Name string; run func(*Scan) } // detect.Secrets, detect.Runs: the order they run in
```

The detectors run in one order, listed once (`internal/detect/registry.go`): each entry is a
root rule's name and its function, and the name is the switch the gate's build turns it off by
(`internal/gate`).

The classifiers are ported as functions, unchanged in meaning:
`IsCredentialName` (the word-set vocabulary), `LooksSecret` / `wordlike`,
`IsIdentifier`, `writtenAsCode`.

Detectors (each one root rule):

| rule | finds | value extent |
|---|---|---|
| R1 named value | a name run, then a separator from one table: `=`, `:`/`: ` (line start or after `{` `,`), JSON `"k":`, code ops (`=` `:=` `=>` `+=` `??=` typed `: T =`, `var x T =`), flag + space, `ENV`/`setx`, quoted name `"K"=`, `&k=` in a quoted word | per separator: shell word, colon words to a stop word, literal, statement literals, code word, array, object, heredoc, YAML block |
| R2 program options | one table of (program, option, attached) on the command's argv: mysql `-p`, sshpass `-p`, `login -p`, redis-cli `-a`, openssl `-k` `-K` `-pass pass:`, curl `-u` `--user` `--proxy-user` `-U`, `secret set --body/-b`, npm `:_authToken` | the shell word (curl: after the user's colon) |
| R3 headers and schemes | header names (`authorization`, `cookie`, `x-api-key`, any credential name after `-H`) and auth schemes (`Bearer x`) | to the quote that closes the header, else the word (scheme + word; cookie pairs) |
| R4 SQL | `PASSWORD 'x'`, `IDENTIFIED BY x` | the SQL literal or word |
| R5 URL userinfo | `scheme://user:PASS@` | to the `@` |
| R6 token formats | the gitleaks-derived prefix table (`internal/tokens/tokens.json`) and JWT, also with written escapes blanked and with a one-letter option attached before it (`-d` then the token) blanked | the format |
| R7 long run | 32+ token characters holding a letter and a digit | the run, kept when a path or an identifier written as code |
| R8 shapes and denylist | email, phone (NANP, international), identities, vendors | the match |

R6-R8 read every reading that is not joined (raw, unescaped, JSON, percent-decoded), so an
address written `bob%40example.com` or a token written `abc\/def` is found decoded. Phones
are not read percent-decoded: there `+` is a space, and a diff's `+` row marker or a URL's
`a+b` would read as a phone's spacing. They are read on the text as written (a `+` row of
digits in text given to `Scrub` is a number, as Python's `scrub()` reads it) and with a diff
hunk's sides apart, markers stripped (as the audit reads them); `ScrubDiff` reads sides only.

A double-dash credential flag (`--password`, `--token`, `--client-secret`, any name
`IsCredentialName` accepts) takes its next word as its value even when that word starts with
a dash, across a line continuation too: a password may start with one. A password-family flag
(`fixedFlag`) takes any such word; another credential's flag leaves one that reads as an option
(`-`, `-v`, `--verbose`; `optionLike`), as the oracle's keep family does; `--name=...` is a value. curl's
short options combine (`-kuadmin:pw`, `-kUadmin:pw`): the `u`/`U` takes the rest of the word.

A YAML line written inside a quoted string (`'  client_secret: "x"'`, `echo "password: x"`, a JSON
string holding `password: x`) is a line head: the string's receiver reads it as its own line, and
the value ends where that string closes (`quotedHeadCloser`). A JWT glued to a word before it is
read with longer segments. `ScrubDiff` also reads addresses on each row as written, its marker never hidden: a diff quoting a diff holds ` +@pytest.mark.x`, which the receiver reads as one. A cut output keeps its `…[cut]` marker within the limit, so it scrubs to
itself, and never ends where the audit reads the marker as a value (`IDENTIFIED BY …[cut]`,
`Authorization:<redacted> …[cut]`, a fullwidth `＝ …[cut]`) or where reading it again would hide more; only
what the marker itself causes drops words, never a hit the kept text already held. An array's value ends at
the `]` that closes it, strings skipped, so a `]` inside an element does not end it.

Known headers (`authorization`, `x-api-key`, `cookie`, ...) written as a field of an object
literal (`{authorization: Digest u="a", response="b"}`) run to the line end: a header value's
own `, k=v` parameters read as the literal's next fields. A credential's `name: value` whose
value is a placeholder and more words (`authorization: <redacted> <token_or_cookie>`) is a
value partly sent, and goes whole.

A generic name never shields a credential: every separator in the text is examined on
its own, so `key=PASSWORD=x` and `{cache_key: a,password: x}` find the inner credential
without any "read on inside the value" machinery.

### 4. Render once (`internal/engine`)

Spans from every reading and detector are unioned in source offsets. Each maximal run
becomes one placeholder (`<redacted>`, `<long-token>`, `<redacted-jwt>`, `[email]`,
`[phone]`, `[owner]`/`[teammate]`/`[person]`, `[vendor]`; a mixed run is `<redacted>`).
In `ScrubDiff` line breaks are never hidden, so every row keeps its place; in `Scrub` a line break inside a hidden value goes with it, as one value. A bracket opened inside a hidden
run is the value's, so its closer right after the run goes with it. The rendered text is then
read again (all detectors, mapped back through the render map) until it holds still, so the
output scrubs to itself. It is read at most 8 more times, as Python's rounds are bounded; still
changing then, what the next round would hide could be a value, so it fails closed as Python's
`_run` does: the lines before the first one that round changes are kept when they hold still,
and otherwise the output is `…[cut]` alone. On each re-read the audit also locates the values it still reads as
sent; one that holds a placeholder and more (`--db-secret=<redacted>`),`) is a value partly
sent and goes whole, so the output passes its own audit. Then the text is cut to `limit`
runes, never ending inside a word.

Where a value is read to a closing quote or a stop word (a quoted word's `&name=` field, a
whole assignment in quotes, a credential's colon words), a placeholder followed by more is
the same: the value goes whole. A credential's `NAME=` value, as a receiver splits it (a quoted
string, or a run to a space or quote), is `<redacted>` alone or it goes whole, a closer or escape
glued to the placeholder too (`f(api_key=<redacted>)` loses its `)`, as Python's audit requires);
so is a JSON field's value read to its quote, and a closed `"NAME=..."` / `'NAME=...'` wherever a
quote opens one (a quote between two placeholders is part of the value, as Python's audit reads
it: `placeholderValue`). Each credential's statement is read from its own name, so two readings
can pair the same quotes differently; where their literals overlap they are one value, opening of
the first to closing of the last, seams included (`litMerge`, as
`scrub_literals.assignment_literals` merges them). Statement literals are read past a heredoc opener (the rest of
its line is the statement too) and past an unclosed literal whose body is already a
placeholder (its quote was paired wrongly; the statement's later literals are read on their
own).

### 5. Diffs (`internal/engine/diff.go`)

One diff reader: hunk headers give each hunk's row counts; each side is assembled as
its file holds it (markers stripped) with an offset map and scrubbed as a reading;
spans map back onto the rows, and every row keeps its marker and line ending. Text
outside hunks, and a diff that breaks its own counts, is read every way at once (as
plain text, with continuations past one marker, and as sides), and the union is hidden.

### 6. The audit (`internal/audit`, `internal/auditnet`)

`Audit(text, denylist) []string` returns rule ids, never text. It reads every reading
of §1 (raw, each unescape level, percent-decoded and then unescaped; JSON values are
decoded first by `AuditBody`), so it reads what the receiver will read. **The readings
are shared with the scrubber, by design: both read through the same decoder, so they
cannot disagree about what the receiver sees.** The checks themselves are deliberately
NOT the scrubber's detectors (one lexer bug must not blind both, the v11 failure):

- `email`, `identity[i]:role`, `vendor[j]` on every reading that is not joined; `phone` on the
  raw text (diff sides apart) and the unescaped readings, as the scrubber reads them;
- `secret:token-format` and `secret:jwt` (its own scan: `eyJ` and three base64url segments) on
  every reading; `secret:long-run` on every reading that is not joined (it shares the long-run
  classifier, so a path or code the scrubber keeps passes);
- `secret:named-value` for code's spaced `name = value` when the value holds a placeholder and more
  (`<redacted>[0]`, `<redacted>/`), as Python's audit splits it at a space, quote or backtick;
- `secret:named-value` also as a receiver splits `NAME=` from what follows (a quoted string, or
  a run to a space or quote): for a credential's name anything there but `<redacted>` is a
  value, `NAME=;` and `<redacted>)` included, as Python's audit reads it; a JSON field's value
  likewise (`"<redacted> "` is a value);
- `secret:named-value` / `secret:json-field` / `secret:colon-value` / `secret:flag-value` /
  `secret:header`: any name-shaped run, a separator, and a value read with the audit's own
  crude extent (to the closing quote, else the word, else the colon words), judged by
  `IsCredentialName` and `LooksSecret`. A value that is entirely placeholders passes. A quoted
  JSON value is read to the quote written as its opener, past an escaped line break, as the
  scrubber reads it. A known header's value in an object literal runs to the line end. A
  quoted header that never closes runs to the next quote or backslash, as Python's audit reads
  it, unless it opens the other quote, when that quoted part is the value. A line break and the
  next diff row's marker between placeholders hold nothing. Dashes past two before a name are a
  flag only before a password-family name (`---passwd x`, not `---DSN start---`). A YAML block
  scalar's body is the lines indented past its key; a sibling key right after it means the block is empty.
  An unquoted header value with anything glued to its placeholder (`X-Token:<redacted>,`) is a value partly
  sent, as is `NAME=` followed by blanks or line breaks and a quoted string holding a placeholder.

## 7. CLI (`cmd/scrub`)

JSONL in, JSONL out, the harness's `scrub` contract:
`{"op": "scrub"|"scrub_diff"|"audit_text"|"audit_body"|"redact", "text": str, "limit": int}`
-> `{"out": str}` or `{"hits": [...]}`. `--denylist PATH`; a bad denylist is one line
`{"denylist_error": "..."}` and exit 1. The error never quotes an entry or a path.

## 8. How it is proven (`harness/`)

The harness reads real-data corpora and the earlier Python scrubber, both private, so it is kept out of the
public tree; this section describes what it measures.

The pass bar is the outcome contract (the nine rules in the README, approved 2026-11-06),
run by `harness/gate.py`; Python's scrubber (v22, frozen) is a regression check, never the target.
`gate.py` exits 0 only when all four measures pass, and contract rules 8 and 9 (below) hold:

- **(a) Planted canaries, 0 survive** (`harness/canary.py`). Fake secrets and identities are made
  from a seed at run time and never saved: random token bodies, a body for every vendor prefix in
  `tokens.json`, JWT shapes, a fake denylist (pseudo-word names, handles, a regex identity,
  vendors), addresses at reserved test domains, phones in fictional ranges (NANP 555-01xx, UK
  drama ranges). One is planted in each real text from `build_corpus.py`, balanced over 25 shapes
  (shell flags, env assignments, JSON fields raw and nested, headers and cookies, Python / JS / Go /
  YAML / SQL literals, URL userinfo and query, bare tokens, JWTs, long runs, names, handles,
  vendors, addresses, phones) by 7 positions (start, middle, end, a line start, a diff's added row,
  across a line continuation, just before the length cut): every cell holds at least 500, at
  least 150,000 in all. Within a cell the encoding cycles: plain, quoted, escaped one and two
  levels, percent-encoded once and twice, HTML entities, `\xNN`, octal, `\u`, fullwidth. A
  survivor is any 6 characters of a canary's body in any reading of the output (the checker's
  own decoder: as written, continuations joined, each backslash level, JSON escapes, percent once
  and twice, HTML, NFKC) that no reading of the unplanted text, the shape around the body or a
  placeholder holds. The out-of-scope rows of section 9 run too, reported and never gated.
- **(b) Both audits pass every Go output**: the canary set, every real corpus, the fixtures and the
  oracle's recorded test calls.
- **(c) Over-redaction budget.** Clean texts are those Python returns unchanged, both audits pass as
  written, and that hold no canary. Go may change at most 0.1% of them, and none of the named keep
  fixtures (`scrub_long_identifiers.txt` and the oracle's "kept" test families). Over-refusals and
  characters hidden beyond Python on texts that hold something may not rise against
  `harness/gate_baseline.json`.
- **(d) Python as a regression check.** Every run of characters Python hides and Go keeps gets a
  targeted canary at exactly that spot (its letters and digits replaced by random ones, its
  punctuation kept). Go hides it and both audits pass: "Python hides more", not a failure.
  Anything else is a gap in Go.

The repository keeps only the generator, the shape templates and counts. Reports name a canary's
id, shape, position and encoding, never the text around it; `--debug-dir` (outside the repository)
adds each failure's synthetic instance and an isolated reproduction, the real text around it
masked. Rule 6 (scrubbing an output again changes nothing) is counted on every canary output.

`harness/diffcheck.py` still runs the byte-level differential (fixtures, recorded tests, the
invariant grid, the frozen releases, the real corpora) as a report: what it calls a leak is what
(d) checks. `SCRUB_PY_CACHE=FILE` (outside the repository) keeps the oracle's answers between runs.
The six-entry intended-drift file and its proofs are retired: (d) settles each such spot.

## 9. Known gaps

The contract (SCRUBBER.md) put the cheap decodes, a JSON string inside a JSON string and fullwidth
letters in scope; they are readings now (section 1) and every one is a canary encoding or shape. What
is left out, by the approved decision, is run as an out-of-scope canary row, reported and never gated:

- Base64 or gzip payloads: only the 32-character long-run rule covers them.
- Look-alike Unicode other than fullwidth (a Cyrillic `о` in a name): needs a confusables table.
- Phones written percent-encoded (`%2B1%20555...`): not read (see R8); reading `+` as a space hides
  diff rows.
- A value whose name is not a credential's and that does not look random (`n: hunter2`), prose that
  names a credential then a short word (`the token is abc`), a cookie on the next line after an empty
  pair, and a second word after a Bearer token (`Authorization: Bearer abc def`): kept, as in Python.
- Mid-sentence, after a weaker credential name (`auth`, `dsn`, `otp`, `pat`), a letters-only word under
  13 letters (`see auth: rotated here`) reads as prose and is kept. After a strong one, whose last word
  is the credential itself (`password`, `secret`, `token`, `api_key`, `DB_PASSWORD`), any plain word
  but a prose word is hidden (`see password: letmein here`).

### Spots Python hides and Go keeps (measure (d))

Python reads a credential's statement from every name and then re-reads its own placeholders, so it
also hides quoted words past where a statement ends, closers and openers beside a hidden value, and a
scheme word. Each such spot gets a targeted canary (section 8). The gated canary is a body rules 2 and
3 require hidden wherever it stands; Go hiding it closes the spot as "Python hides more". The
informational one (the spot's own letters and digits replaced at random) is required hidden only where
the spot is a credential's value, so its survival is counted and reported, never gated: no port of
Python's pass order, and no hiding of whole statements.
