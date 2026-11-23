package reading

import (
	"strings"
	"unicode/utf8"

	"github.com/0xbew/scrub/internal/lex"
)

// percentDecode reads `%XX` as its byte and `+` as a space, as a URL's receiver does.
func (r *Reading) percentDecode() *Reading { return r.percentDecodeAs(true) }

// percentDecodeAs reads `%XX` as its byte; with plus, `+` as a space too (a form body or a query), without it
// `+` stays (a path, or text that only escapes some bytes).
func (r *Reading) percentDecodeAs(plus bool) *Reading {
	s := r.Text
	out := &Reading{Kind: readPercent, Pct: plus || r.Pct, Pctd: true, Src: r.Src}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b = append(b, h<<4|l)
				out.Lo = append(out.Lo, r.Lo[i])
				out.Hi = append(out.Hi, r.Hi[i+2])
				i += 2
				continue
			}
		}
		c := s[i]
		if c == '+' && plus {
			c = ' '
		}
		b = append(b, c)
		out.Lo = append(out.Lo, r.Lo[i])
		out.Hi = append(out.Hi, r.Hi[i])
	}
	out.Text = string(b)
	return out
}

// readings: the text as written, each level of backslash escaping removed, and the same decoded (when decode is
// set): percent-decoded (`+` kept, and `+` as a space), HTML entities, fullwidth letters folded, continuations
// joined, and up to two of these in turn (`%2522` is `%22` is `"`). Each level that holds a JSON string's escapes
// is also read as one (not read further down). Duplicates are dropped.
func Of(base *Reading, decode bool) []*Reading {
	seen := map[string]bool{base.Text: true}
	out := []*Reading{base}
	starts := []*Reading{base}
	if decode {
		starts = decodedStarts(base, seen, starts)
	}
	return escapeLevels(starts, seen, out)
}

// decodedStarts: starts with base's continuations joined and up to two decodings in turn
// appended, each one not seen before (and marked seen).
func decodedStarts(base *Reading, seen map[string]bool, starts []*Reading) []*Reading {
	frontier := []*Reading{base}
	// A continuation is joined first, as a shell joins it before anything decodes what it wrote; the two
	// decodings after it may then read an escape the continuation split (`%25` `\`-newline `20`).
	if strings.Contains(base.Text, "\\\n") || strings.Contains(base.Text, "\\\r\n") {
		j := base.joinConts()
		if !seen[j.Text] {
			seen[j.Text] = true
			starts = append(starts, j)
			frontier = append(frontier, j)
		}
	}
	for depth := 0; depth < 2 && len(frontier) > 0; depth++ {
		frontier, starts = decodeFrontier(frontier, seen, starts)
	}
	return starts
}

// decodeFrontier: the decodings of each reading of frontier not seen before (marked seen), as
// the next frontier, and starts with them appended.
func decodeFrontier(frontier []*Reading, seen map[string]bool, starts []*Reading) (next, more []*Reading) {
	for _, r := range frontier {
		for _, d := range r.decodings() {
			if !seen[d.Text] {
				seen[d.Text] = true
				starts = append(starts, d)
				next = append(next, d)
			}
		}
	}
	return next, starts
}

// escapeLevels: out with each start after the first appended, each followed by the levels of
// backslash escaping removed from it (and each level's JSON string reading) not seen before.
func escapeLevels(starts []*Reading, seen map[string]bool, out []*Reading) []*Reading {
	add := func(r *Reading) {
		if !seen[r.Text] {
			seen[r.Text] = true
			out = append(out, r)
		}
	}
	for si, start := range starts {
		level := start
		if si > 0 {
			out = append(out, level)
		}
		unescapeLevels(level, add)
	}
	return out
}

// unescapeLevels: each level of backslash escaping removed from level in turn, up to
// maxEscapeLevels, and each level that holds a JSON string's escapes read as one, passed to add.
func unescapeLevels(level *Reading, add func(*Reading)) {
	for range maxEscapeLevels {
		if hasJSONEscape(level.Text) {
			add(level.unescape(true))
		}
		next := level.unescape(false)
		if next.Text == level.Text {
			break
		}
		level = next
		add(level)
	}
}

// decodings: each decoding a receiver may apply to r that changes it.
func (r *Reading) decodings() []*Reading {
	var out []*Reading
	s := r.Text
	if strings.IndexByte(s, '%') >= 0 {
		if p := r.percentDecodeAs(false); p.Text != s {
			out = append(out, p)
		}
	}
	// A form body reads `+` as a space even where nothing is percent-encoded.
	if strings.IndexByte(s, '+') >= 0 {
		if p := r.percentDecodeAs(true); p.Text != s {
			out = append(out, p)
		}
	}
	if strings.IndexByte(s, '&') >= 0 {
		if h := r.htmlDecode(); h.Text != s {
			out = append(out, h)
		}
	}
	if strings.Contains(s, "\xef\xbc") || strings.Contains(s, "\xef\xbd") || strings.Contains(s, "\xe3\x80\x80") {
		out = append(out, r.foldWidth())
	}
	// Not after `+` was read as a space: a diff row's marker is gone there, and its rows would run together.
	if !r.Pct && (strings.Contains(s, "\\\n") || strings.Contains(s, "\\\r\n")) {
		out = append(out, r.joinConts())
	}
	return out
}

// derived: a reading built byte by byte from r, each byte mapped through r to the source.
type derived struct {
	r   *Reading
	out *Reading
	b   []byte
}

func (r *Reading) derive(kind readingKind) *derived {
	return &derived{r: r, out: &Reading{Kind: kind, Pct: r.Pct, Pctd: r.Pctd, Joined: r.Joined, Src: r.Src}}
}

// emit writes c as standing for r's bytes [i, j).
func (d *derived) emit(c byte, i, j int) {
	lo, hi := d.r.Source(i, j)
	d.b = append(d.b, c)
	d.out.Lo = append(d.out.Lo, int32(lo))
	d.out.Hi = append(d.out.Hi, int32(hi))
}

func (d *derived) emitRune(c rune, i, j int) {
	var buf [4]byte
	for _, b := range buf[:utf8.EncodeRune(buf[:], c)] {
		d.emit(b, i, j)
	}
}

func (d *derived) done() *Reading {
	d.out.Text = string(d.b)
	return d.out
}

// htmlEntities: the named entities a page's text decodes that can stand for a value's own bytes.
var htmlEntities = map[string]rune{
	"quot": '"', "amp": '&', "lt": '<', "gt": '>', "apos": '\'', "nbsp": ' ', "equals": '=', "colon": ':',
	"sol": '/', "bsol": '\\', "num": '#', "percnt": '%', "plus": '+', "comma": ',', "period": '.', "semi": ';',
	"lpar": '(', "rpar": ')', "lsqb": '[', "rsqb": ']', "lcub": '{', "rcub": '}', "excl": '!', "quest": '?',
	"ast": '*', "dollar": '$', "commat": '@', "lowbar": '_', "hyphen": '-', "grave": '`', "Hat": '^',
	"vert": '|', "tilde": '~', "Tab": '\t', "NewLine": '\n',
}

// htmlDecode reads `&name;`, `&#NN;` and `&#xHH;` as the character each stands for.
func (r *Reading) htmlDecode() *Reading {
	s := r.Text
	d := r.derive(readDecoded)
	for i := 0; i < len(s); i++ {
		if s[i] == '&' {
			if c, n := htmlEntityAt(s, i); n > 0 {
				d.emitRune(c, i, i+n)
				i += n - 1
				continue
			}
		}
		d.emit(s[i], i, i+1)
	}
	return d.done()
}

// htmlEntityAt: the character an entity at i stands for and its length, 0 when there is none.
func htmlEntityAt(s string, i int) (rune, int) {
	j := i + 1
	if j < len(s) && s[j] == '#' {
		return htmlNumericEntityAt(s, i, j+1)
	}
	k := j
	for k < len(s) && k-j < 10 && lex.IsAlnumASCII(s[k]) {
		k++
	}
	if k < len(s) && s[k] == ';' {
		if c, ok := htmlEntities[s[j:k]]; ok {
			return c, k + 1 - i
		}
	}
	return 0, 0
}

// htmlNumericEntityAt: the character a numeric entity at i (`&#65;`, `&#x41;`) stands for and its
// length, j just after its `#`; 0 when it is none or no valid character.
func htmlNumericEntityAt(s string, i, j int) (rune, int) {
	base := 10
	if j < len(s) && (s[j] == 'x' || s[j] == 'X') {
		base = 16
		j++
	}
	v, k := htmlEntityDigits(s, j, base)
	if k == j || k >= len(s) || s[k] != ';' || v == 0 || v > utf8.MaxRune || (v >= 0xD800 && v < 0xE000) {
		return 0, 0
	}
	return rune(v), k + 1 - i
}

// htmlEntityDigits: the value of up to 7 digits in base from j, and where they end.
func htmlEntityDigits(s string, j, base int) (v, k int) {
	v, k = 0, j
	for k < len(s) && k-j < 7 {
		h, ok := unhex(s[k])
		if !ok || int(h) >= base {
			break
		}
		v = v*base + int(h)
		k++
	}
	return v, k
}

// foldWidth reads fullwidth forms (U+FF01..U+FF5E) as their ASCII characters and the ideographic space as a space.
func (r *Reading) foldWidth() *Reading {
	s := r.Text
	d := r.derive(readDecoded)
	for i := 0; i < len(s); {
		c, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case c >= 0xFF01 && c <= 0xFF5E:
			d.emit(byte(c-0xFEE0), i, i+n)
		case c == 0x3000:
			d.emit(' ', i, i+n)
		default:
			for k := i; k < i+n; k++ {
				d.emit(s[k], k, k+1)
			}
		}
		i += n
	}
	return d.done()
}

// looksLikeDiff: a line opens a hunk (`@@ -`). A `--- ` line alone is as often a Markdown rule.
func looksLikeDiff(s string) bool {
	return strings.HasPrefix(s, "@@ -") || strings.Contains(s, "\n@@ -")
}

// joinConts reads a line continuation (`\` then a line break) as nothing, as a shell joins the two lines; into a
// diff row, the row's marker goes with it.
func (r *Reading) joinConts() *Reading {
	s := r.Text
	d := r.derive(readDecoded)
	diff := looksLikeDiff(s)
	for i := 0; i < len(s); i++ {
		if n := lex.ContAt(s, i); n > 0 {
			i = joinContAt(d, s, i, n, diff)
			continue
		}
		d.emit(s[i], i, i+1)
	}
	return d.done()
}

// joinContAt: the continuation of n bytes at i read as nothing, unless it runs into a diff's row
// of the other side: the index the next byte is read after.
func joinContAt(d *derived, s string, i, n int, diff bool) int {
	if k := i + n; k < len(s) && (s[k] == '+' || s[k] == '-') {
		// Into a diff's `+` or `-` row: a row of blanks then content joins without its marker. In a diff,
		// another is the other side's row, and a shell on this side never reads it.
		if k+1 < len(s) && (s[k+1] == ' ' || s[k+1] == '\t') {
			return i + n
		}
		// Or a row of the other side right after this one (`-x \` then `+y`), headers or not.
		if cur := s[lex.LineStart(s, i)]; diff || ((cur == '+' || cur == '-') && cur != s[k]) {
			d.emit(s[i], i, i+1)
			return i
		}
	}
	return i + n - 1
}

// hasJSONEscape: `\n` `\r` `\t`, `\uXXXX`, `\xNN` or an octal escape somewhere in s.
func hasJSONEscape(s string) bool {
	for i := strings.IndexByte(s, '\\'); i >= 0 && i+1 < len(s); i = lex.NextByte(s, '\\', i+2) {
		if jsonEscapeAt(s, i) {
			return true
		}
	}
	return false
}

// jsonEscapeAt: the backslash at i (with a byte after it) opens `\n` `\r` `\t`, a `\uXXXX`
// that decodes to a rune (a surrogate only as a whole pair), a `\xNN`, or an octal digit.
func jsonEscapeAt(s string, i int) bool {
	switch c := s[i+1]; {
	case c == 'n' || c == 'r' || c == 't' || (c >= '0' && c <= '7'):
		return true
	case c == 'u':
		if _, n := unicodeEscape(s, i); n > 0 {
			return true
		}
	case c == 'x':
		if i+3 < len(s) {
			if _, ok := unhex(s[i+2]); ok {
				if _, ok := unhex(s[i+3]); ok {
					return true
				}
			}
		}
	}
	return false
}
