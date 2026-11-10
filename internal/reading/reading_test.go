package reading

import (
	"testing"

	"github.com/0xbew/scrub/internal/lex"
)

// The readings' offset maps: each decoded byte must name the source bytes a receiver decoded
// it from, so a value found there hides its source. Cases are the phase-2 leak shapes.
func TestReadingsMapEachByteToItsSource(t *testing.T) {
	type span struct{ lo, hi int }
	cases := []struct {
		name   string
		src    string
		read   func(*Reading) *Reading
		text   string
		at     int  // a byte of text
		from   span // the source span it came from
		joined bool
	}{
		// A JSON string's `\n` is a line break: the break stands for both source bytes.
		{"json line break", `ls\n--token x`, func(r *Reading) *Reading { return r.unescape(true) }, "ls\n--token x", 2, span{2, 4}, false},
		// Read as a plain escape it is the letter, and the words either side run together.
		{"plain escape", `ls\n--token x`, func(r *Reading) *Reading { return r.unescape(false) }, "lsn--token x", 2, span{2, 4}, true},
		// A JSON string's unicode escape of `=` is `=`.
		{"json unicode", "token\\u003dabc", func(r *Reading) *Reading { return r.unescape(true) }, "token=abc", 5, span{5, 11}, false},
		// An escaped quote is its backslash and itself.
		{"escaped quote", `{\"k\": 1}`, func(r *Reading) *Reading { return r.unescape(false) }, `{"k": 1}`, 1, span{1, 3}, false},
		// Percent-encoded: `%22` is one quote of three source bytes; `+` is a space.
		{"percent", `%22a+b%22`, func(r *Reading) *Reading { return r.percentDecode() }, `"a b"`, 4, span{6, 9}, false},
		// A JSON string's \u escape past ASCII is its character's UTF-8 bytes, each from the whole escape; a
		// surrogate pair is one character, from both escapes.
		{"json unicode past ASCII", "a\\u00e9\\ud83d\\ude00b", func(r *Reading) *Reading { return r.unescape(true) }, "aé😀b", 1, span{1, 7}, false},
		{"json surrogate pair", "a\\u00e9\\ud83d\\ude00b", func(r *Reading) *Reading { return r.unescape(true) }, "aé😀b", 3, span{7, 19}, false},
		{"json unicode past ASCII, last byte", "a\\u00e9\\ud83d\\ude00b", func(r *Reading) *Reading { return r.unescape(true) }, "aé😀b", 2, span{1, 7}, false},
		{"json surrogate pair, last byte", "a\\u00e9\\ud83d\\ude00b", func(r *Reading) *Reading { return r.unescape(true) }, "aé😀b", 6, span{7, 19}, false},
	}
	for _, c := range cases {
		r := c.read(Raw(c.src))
		if r.Text != c.text {
			t.Errorf("%s: text %q, want %q", c.name, r.Text, c.text)
			continue
		}
		if lo, hi := r.Source(c.at, c.at+1); lo != c.from.lo || hi != c.from.hi {
			t.Errorf("%s: byte %d from [%d,%d), want [%d,%d)", c.name, c.at, lo, hi, c.from.lo, c.from.hi)
		}
		if r.Joined != c.joined {
			t.Errorf("%s: joined %v, want %v", c.name, r.Joined, c.joined)
		}
	}
}

// A quoted value ends at a quote written as its opener, past a line break written as a
// continuation. Both are phase-2 leaks: the value's tail was sent.
func TestAQuotedValueEndsAtItsOwnClosingQuote(t *testing.T) {
	cases := []struct {
		name, src string
		read      func(*Reading) *Reading
		open      int // the opening quote in the reading
		want      int // the end of the value in the reading (just past its closing quote)
	}{
		// `%22TOKEN%22%3A%22abc"Vq7zLmQ%22`: the raw `"` is the value's, `%22` closes it.
		{"raw quote in an encoded value", `%22abc"Vq7zLmQ%22 x`, func(r *Reading) *Reading { return r.percentDecode() }, 0, 13},
		// `\"zq9\<newline>tail\"` one level down: the escaped break continues the value.
		{"continued line break", "\\\"zq9\\\ntail\\\" x", func(r *Reading) *Reading { return r.unescape(false) }, 0, 10},
		// A quote written as the opener closes it: nothing more is read.
		{"closed", `"abc" "def"`, func(r *Reading) *Reading { return r }, 0, 5},
	}
	for _, c := range cases {
		r := c.read(Raw(c.src))
		if got := r.QuotedEnd(r.Text, c.open, lex.DqEndLine); got != c.want {
			t.Errorf("%s: %q ends at %d, want %d", c.name, r.Text, got, c.want)
		}
	}
}
