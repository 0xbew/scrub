package detect

import (
	"testing"

	"github.com/0xbew/scrub/internal/lex"
)

// Lexer extents, with the expected end from shell and object-literal grammar.
func TestValueExtents(t *testing.T) {
	cases := []struct {
		name string
		got  func() int
		want int
	}{
		// bash: quoted and bare parts glue into one word.
		{"glued shell word", func() int { return lex.ValueEnd(`"ab"cd'ef' x`, 0) }, 10},
		// bash: an escaped space continues the word.
		{"escaped space", func() int { return lex.ValueEnd(`ab\ cd x`, 0) }, 6},
		// An object literal's value ends before the `}` that closes the literal.
		{"flow words", func() int { return colonWords("ab Vq7zLmQ}", 0, true, false) }, 11},
		// A double-quoted string honours its escapes to the closing quote on its line.
		{"dq escapes", func() int { return lex.DqEndLine(`"a\"b" c`, 0) }, 6},
		// A `]` inside a string does not close the array (review finding: the element after it
		// was sent).
		{"array past a quoted bracket", func() int { return ArrayEnd(`["x]", "abc"] y`, 0) }, 12},
		// Unclosed, it runs to the line end.
		{"dq unclosed", func() int { return lex.DqEndLine("\"ab\ncd", 0) }, 3},
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
