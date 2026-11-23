package detect

import (
	"strings"

	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/vocab"
)

// proseWords: a word that, after a credential's name mid-sentence, is the sentence going on, not a value
// (`the token: it expires`, `password: required`).
var proseWords = lex.SetOf("a", "an", "the", "is", "are", "was", "were", "be", "been", "it", "its", "this", "that", "these",
	"those", "and", "or", "not", "no", "yes", "to", "of", "in", "on", "for", "with", "from", "by", "at", "as", "if",
	"then", "when", "which", "who", "what", "how", "why", "where", "we", "you", "he", "she", "they", "i", "my", "your",
	"our", "their", "has", "have", "had", "do", "does", "did", "can", "could", "should", "would", "will", "may",
	"might", "must", "set", "unset", "use", "used", "using", "see", "null", "none", "nil", "true", "false", "empty",
	"required", "optional", "string", "str", "int", "number", "any", "unknown", "missing", "invalid", "expired",
	"needed", "here", "there", "same", "new", "old", "all", "each", "every", "only", "also", "just", "now", "redacted",
	"hidden", "masked", "secret", "value", "values", "none", "undefined", "todo", "tbd", "n/a", "xxx", "changeme")

// proseValue: the word at a credential's name mid-sentence is prose (or code), not a value.
func proseValue(v string) bool {
	w := strings.ToLower(strings.TrimRight(strings.Trim(v, "\"'`"), ".,;:!?)"))
	return w == "" || proseWords[w]
}

// strongProse: verbs a sentence or a commit message puts after a credential's name (`Fix token: refresh it`).
var strongProse = lex.SetOf("refresh", "refreshed", "rotate", "rotated", "reset", "revoke", "revoked", "renew", "renewed",
	"regenerate", "regenerated", "update", "updated", "change", "changed", "fix", "fixed", "add", "added", "remove",
	"removed", "check", "checked", "verify", "verified", "validate", "validated", "store", "stored", "save", "saved",
	"load", "loaded", "read", "write", "send", "sent", "handle", "handled", "parse", "parsed", "support", "clean",
	"expire", "expires", "rename", "renamed", "move", "moved", "keep", "kept", "drop", "dropped")

// plainWord: one word of three or more letters only that is not the sentence going on (`letmein`, not `required`
// or `refresh`).
func plainWord(v string) bool {
	if len(v) < 3 || proseValue(v) || strongProse[strings.ToLower(v)] {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !lex.IsLowerASCII(v[i]) && !lex.IsUpperASCII(v[i]) {
			return false
		}
	}
	return true
}

// minProseLongWord: mid-sentence, after a weaker credential name, a word of letters only this long or longer is a
// value; a shorter one is the sentence going on (`auth: rotated`), as an English word that long is rare.
const minProseLongWord = 13

// valueLike: mid-sentence, a word after a credential's name that reads as a value: holding a digit or a character
// no English word or identifier holds, or letters only and long; a short run of digits (`password: 0`) is a count,
// and letters joined by `-` `_` `.` are an identifier (`secret_scope`, `api-key-name`).
func valueLike(v string) bool {
	if v == "" || proseValue(v) {
		return false
	}
	digits, letters, sep, other := 0, 0, 0, 0
	for i := 0; i < len(v); i++ {
		switch ch := v[i]; {
		case lex.IsDigitASCII(ch):
			digits++
		case lex.IsLowerASCII(ch) || lex.IsUpperASCII(ch):
			letters++
		case ch == '-' || ch == '_' || ch == '.':
			sep++
		case ch <= ' ':
			return false // more than one word: a sentence
		case ch == '\'' && i > 0 && letters == i:
			return false // a possessive or a contraction (`someone's`, `don't`)
		default:
			other++
		}
	}
	switch {
	case letters == 0 && other == 0:
		return digits >= 6
	case digits > 0 || other > 0:
		return true
	case sep > 0:
		return false
	}
	if letters < minProseLongWord {
		return false
	}
	// Letters only and long: all lower case (no English word that long follows a credential's name), or upper
	// case mixed in at random; a type name's humps (`CredentialProvider`) are a few capitals in many letters.
	upper := 0
	for i := 1; i < len(v); i++ {
		if lex.IsUpperASCII(v[i]) {
			upper++
		}
	}
	return upper == 0 && lex.IsLowerASCII(v[0]) || upper*4 >= letters
}

// midValue: the value after a credential's name mid-sentence, from v: a quoted string that opens here and closes
// on its line (its body), else the word to a blank (after a quote that never closes), without the wrapping a writer puts around it (`**x**`,
// “ `x` “, `${x}`, curly quotes) or the punctuation that ends the sentence. A quote that closes a string opened
// earlier (`"invalid token: " + t`) holds no value. Returns the span to judge and hide, or ok false.
func midValue(s string, v int) (lo, hi int, ok bool) {
	le := lex.LineEnd(s, v)
	if q := s[v]; q == '"' || q == '\'' || q == '`' {
		k := strings.IndexByte(s[v+1:le], q)
		if k == 0 {
			return 0, 0, false
		}
		if k > 0 {
			return v + 1, v + 1 + k, true
		}
		// A quote that does not close on its line: the word right after it is the value. One that closes a
		// string opened earlier (`"invalid token: "+t`, `"token: "*(n//2)`) or opens a template (`"{{ .Pw }}`)
		// holds none.
		v++
		if v >= le || lex.IsSpaceByte(s[v]) || strings.IndexByte("+*{<(%)]},;.|&!?", s[v]) >= 0 || s[v] == '$' && isReference(s, v) {
			return 0, 0, false
		}
	}
	e := v
	// A written escape (`\n` in a JSON string) ends the word: the next line's text is not the value.
	for e < le && !lex.IsSpaceByte(s[e]) && !(s[e] == '\\' && e+1 < le && lex.IsAlnumASCII(s[e+1])) {
		e++
	}
	lo, hi = v, e
	for _, w := range []string{"**", "*", "${", "“", "‘", "(", "[", "<"} {
		if strings.HasPrefix(s[lo:hi], w) {
			lo += len(w)
			break
		}
	}
	for hi > lo {
		if strings.IndexByte(".,;:!?)]}>*`\"'", s[hi-1]) >= 0 {
			hi--
			continue
		}
		if strings.HasSuffix(s[lo:hi], "”") || strings.HasSuffix(s[lo:hi], "’") {
			hi -= len("”")
			continue
		}
		break
	}
	return lo, hi, hi > lo
}

// midColon: `name: value` in the middle of a line (`see HEROKU_API_KEY: c55d… here`). A credential's name
// hides the word after it when that word reads as a value; another keyword name hides a token word that looks
// random. Only a name standing as a word of its own; without a blank after the colon only a value with a digit
// (`password:Zk3mQ9`), so a URL's scheme or a time is not read.
func (c *Scan) midColon(name string, q, p int) {
	s := c.S
	q = dottedOwnerStart(s, q)
	if q > 0 && !(lex.IsSpaceByte(s[q-1]) || strings.IndexByte(";\"'`([<>*", s[q-1]) >= 0) {
		return
	}
	lo, hi, v := midColonValue(s, p)
	if lo < 0 {
		return
	}
	spaced := s[p+1] == ' ' || s[p+1] == '\t'
	val := s[lo:hi]
	if !spaced && (!vocab.IsCredentialName(name) || !strings.ContainsAny(val, "0123456789") || s[v] == '/') {
		return
	}
	// After a bracket a name and a colon may be a parameter and its type (`async (token: Promise<Token>) =>`):
	// only a value that looks random, or holds a digit and no type brackets, goes there.
	if q > 0 && strings.IndexByte("([<", s[q-1]) >= 0 && !vocab.LooksSecret(val) &&
		(!strings.ContainsAny(val, "0123456789") || strings.ContainsAny(val, "<>")) {
		return
	}
	c.hideMidValue(name, lo, hi)
}

// dottedOwnerStart: where the owners before a name at q start (`db.` in `db.password:`, `spring.datasource.`), or q
// when no `.` stands right before it.
func dottedOwnerStart(s string, q int) int {
	for q > 1 && s[q-1] == '.' {
		o := q - 1
		for o > 0 && (lex.IsAlnumASCII(s[o-1]) || s[o-1] == '_' || s[o-1] == '-') {
			o--
		}
		if o == q-1 || !isIdentStart(s[o]) || s[o] == '$' {
			return q
		}
		q = o
	}
	return q
}

// isReference: a shell or template reference at v, not a value: `${x}`, `$(cmd)`, `$$`, `$1`, `$5k`, or a variable's
// name (`$TOKEN`, `$db_pass`, `$myPassword`). A crypt hash (`$2b$12$...`, `$bcrypt-sha256$...`) or a name mixing
// cases and digits (`$Ab9CDEFgH2`) is a value.
func isReference(s string, v int) bool {
	if cryptHeadEnd(s, v) > 0 {
		return false
	}
	j := v + 1
	if j >= len(s) || s[j] == '{' || s[j] == '(' || s[j] == '$' {
		return true
	}
	upper, lower, digit := false, false, false
	for ; j < len(s) && (lex.IsAlnumASCII(s[j]) || s[j] == '_'); j++ {
		upper = upper || lex.IsUpperASCII(s[j])
		lower = lower || lex.IsLowerASCII(s[j])
		digit = digit || lex.IsDigitASCII(s[j])
	}
	if j < len(s) && (lex.IsWordAt(s, j) || s[j] == '$') {
		return false
	}
	if lex.IsDigitASCII(s[v+1]) {
		return true
	}
	return !upper || !lower || !digit
}

// midColonValue: the value after the colon at p (lo, hi) and where its first byte is (v); lo is
// -1 when nothing follows the colon, when what follows is a reference, a format directive, a
// placeholder, a type or a block indicator, or when no value is read or it is a placeholder.
func midColonValue(s string, p int) (lo, hi, v int) {
	if p+1 >= len(s) {
		return -1, 0, 0
	}
	v = lex.SkipBlanks(s, p+1)
	// A reference, a format directive or a placeholder (`$TOKEN`, `%{http_code}`, `<redacted>`) is not a value.
	if v >= len(s) || s[v] == '$' && isReference(s, v) || s[v] == '%' || opensObject(s, v) || StartsPlaceholder(s, v) || IsTypeWord(s, v) || IsBlockIndicator(s, v) {
		return -1, 0, 0
	}
	lo, hi, ok := midValue(s, v)
	// A placeholder inside the wrapping (`<<redacted>>`) is a value already hidden.
	if !ok || StartsPlaceholder(s, lo) {
		return -1, 0, 0
	}
	return lo, hi, v
}

// hideMidValue: hides the value s[lo:hi] after a mid-line colon: after a credential's name when
// it reads as a value, after another name when it is a token word that judged accepts.
func (c *Scan) hideMidValue(name string, lo, hi int) {
	s := c.S
	val := s[lo:hi]
	if vocab.IsCredentialName(name) {
		// After a strong name a plain word is the value with a bracket after a blank too (`letmein (old)`): only one
		// glued to it is a call or an index.
		strong := vocab.StrongCredentialName(name) && plainWord(val) && !(hi < len(s) && (s[hi] == '(' || s[hi] == '['))
		if strong || valueLike(val) && (!IsCodeValue(s, lo) || vocab.LooksSecret(val)) {
			c.hideValue(lo, hi)
		}
		return
	}
	if tokenWord(val) && judged(name, val) {
		c.hideValue(lo, hi)
	}
}

// tokenWord: one word of token characters, quotes around it allowed: not code or a sentence.
func tokenWord(v string) bool {
	v = strings.Trim(v, "\"'")
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if ch := v[i]; !lex.IsAlnumASCII(ch) && strings.IndexByte("-_+/=.~:", ch) < 0 {
			return false
		}
	}
	return true
}
