package engine

import (
	"strings"
	"unicode/utf8"

	"github.com/0xbew/scrub/internal/detect"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/reading"
	"github.com/0xbew/scrub/internal/span"
	"github.com/0xbew/scrub/internal/vocab"
)

func label(kinds uint16) string {
	secret := kinds & (1<<span.KindSecret | 1<<span.KindLong | 1<<span.KindJWT)
	switch {
	case secret == 1<<span.KindLong && kinds == secret:
		return lex.PhLong
	case secret == 1<<span.KindJWT && kinds == secret:
		return lex.PhJWT
	case secret != 0:
		return lex.PhRedacted
	case kinds&(1<<span.KindEmail) != 0:
		return "[email]"
	case kinds&(1<<span.KindPhone) != 0:
		return "[phone]"
	case kinds&(1<<span.KindOwner) != 0:
		return "[owner]"
	case kinds&(1<<span.KindTeammate) != 0:
		return "[teammate]"
	case kinds&(1<<span.KindPerson) != 0:
		return "[person]"
	case kinds&(1<<span.KindVendor) != 0:
		return "[vendor]"
	}
	return lex.PhRedacted
}

// render replaces each maximal run of hidden bytes with one placeholder. With keepLines, a
// line break is never hidden; otherwise one inside a hidden span goes with it, as one value.
// It also returns, for each output byte, the source span it stands for.
func render(s string, spans *span.Set, keepLines bool) (string, [][2]int) {
	mask := make([]uint16, len(s))
	for _, sp := range spans.Spans {
		lo, hi := sp.Lo, sp.Hi
		if lo < 0 {
			lo = 0
		}
		if hi > len(s) {
			hi = len(s)
		}
		for i := lo; i < hi; i++ {
			mask[i] |= 1 << sp.Kind
		}
	}
	// Whole runes: a run never splits one.
	for i := 0; i < len(s); i++ {
		if mask[i] != 0 && s[i] >= utf8.RuneSelf {
			j := i
			for j > 0 && s[j]&0xC0 == 0x80 {
				j--
			}
			_, sz := utf8.DecodeRuneInString(s[j:])
			for k := j; k < j+sz && k < len(s); k++ {
				mask[k] |= mask[i]
			}
		}
	}
	// A bracket opened inside a hidden run is the value's: its closer right after goes too.
	for i := 0; i < len(s); {
		if mask[i] == 0 {
			i++
			continue
		}
		j := i
		var open []byte
		for j < len(s) && mask[j] != 0 {
			switch s[j] {
			case '(', '[', '{':
				open = append(open, s[j])
			case ')', ']', '}':
				if len(open) > 0 && open[len(open)-1] == opener(s[j]) {
					open = open[:len(open)-1]
				}
			}
			j++
		}
		for j < len(s) && len(open) > 0 && opener(s[j]) == open[len(open)-1] {
			mask[j] = mask[j-1]
			open = open[:len(open)-1]
			j++
		}
		i = j
	}
	// A lone quote between two hidden runs is a value's, paired wrongly: it goes with them.
	for i := 1; i+1 < len(s); i++ {
		if mask[i] == 0 && (s[i] == '"' || s[i] == '\'') && mask[i-1] != 0 && mask[i+1] != 0 {
			mask[i] = mask[i-1]
		}
	}
	isBreak := func(i int) bool { return s[i] == '\n' || s[i] == '\r' }
	var b strings.Builder
	var src [][2]int
	i := 0
	for i < len(s) {
		if mask[i] == 0 || (keepLines && isBreak(i)) {
			b.WriteByte(s[i])
			src = append(src, [2]int{i, i + 1})
			i++
			continue
		}
		j := i
		var kinds uint16
		for j < len(s) && mask[j] != 0 && !(keepLines && isBreak(j)) {
			kinds |= mask[j]
			j++
		}
		ph := label(kinds)
		b.WriteString(ph)
		for k := 0; k < len(ph); k++ {
			src = append(src, [2]int{i, j})
		}
		i = j
	}
	return b.String(), src
}

// opener: the bracket a closer closes, or 0.
func opener(c byte) byte {
	switch c {
	case ')':
		return '('
	case ']':
		return '['
	case '}':
		return '{'
	}
	return 0
}

// fixup: a value that holds a placeholder and anything else is a value partly sent: the
// whole value goes. Read in every reading of the rendered text; emit takes rendered offsets.
func fixup(out string, emit func(lo, hi int)) {
	for _, r := range reading.Of(reading.Raw(out), true) {
		t := r.Text
		for p := strings.IndexByte(t, '='); p >= 0; p = lex.NextByte(t, '=', p+1) {
			q := lex.NameRunBefore(t, p)
			if q == p {
				continue
			}
			name := lex.TrimDashes(t[q:p])
			if name == "" || !(vocab.IsCredentialName(name) || detect.HasKeyword(name)) {
				continue
			}
			lo, hi := auditWordAt(t, p+1)
			inQuotes := false
			// A quoted word that opens with the assignment holds its value to its closing quote.
			if q > 0 && (t[q-1] == '"' || t[q-1] == '\'') {
				inQuotes = true
				e := p + 1
				for e < len(t) && t[e] != t[q-1] && t[e] != '\n' {
					e++
				}
				if e > hi {
					hi = e
				}
			}
			v := t[lo:hi]
			if !strings.Contains(v, "<redacted") && !strings.Contains(v, "<long-token>") {
				continue
			}
			// A credential's value, as a receiver splits it from `NAME=` (a quoted string, or a run to a
			// space or quote), is the placeholder alone or it is a value partly sent: a closer or an
			// escape glued to it (`api_key=<redacted>)`) goes with it.
			bare := strings.Trim(t[lo:hi], "\"'")
			strict := !inQuotes && vocab.IsCredentialName(name) && bare != "" && bare != lex.PhRedacted
			if !strict && (lex.OnlyPlaceholders(v) || (!inQuotes && detect.HeldOnlyAt(t, lo, hi))) {
				continue
			}
			if len(v) > 1 && (v[0] == '"' || v[0] == '\'') {
				lo++
				if v[len(v)-1] == v[0] {
					hi--
				}
			}
			olo, ohi := r.Source(lo, hi)
			if olo < ohi {
				emit(olo, ohi)
			}
		}
	}
}

// auditWordAt: the receiver's reading of a value after `=`: `"..."?`, `'...'?`, or a run
// without a space or quote.
func auditWordAt(s string, i int) (int, int) {
	if i >= len(s) {
		return i, i
	}
	switch s[i] {
	case '"':
		return i, lex.DqEndLine(s, i)
	case '\'':
		le := lex.LineEnd(s, i+1)
		if k := strings.IndexByte(s[i+1:le], '\''); k >= 0 {
			return i, i + k + 2
		}
		return i, le
	}
	j := i
	for j < len(s) && !lex.IsSpaceByte(s[j]) && s[j] != '"' && s[j] != '\'' {
		j++
	}
	return i, j
}
