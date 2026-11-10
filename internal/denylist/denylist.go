package denylist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0xbew/scrub/internal/gate"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/span"
)

const minVendorChars = 3

// Error: the denylist cannot be used. The message never quotes an entry or a path.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

// ErrMissing: there is no local copy.
var ErrMissing = &Error{"no local denylist"}

type Identity struct {
	Rule    string
	Rx      *regexp.Regexp
	Literal bool
	kind    span.Kind
}

type vendor struct {
	Rule string
	Rx   *regexp.Regexp
}

// List is a compiled identity and vendor list, applied whole or refused whole.
type List struct {
	Version    int
	Identities []Identity
	Vendors    []vendor
}

// None: the shapes and secrets only, for a sender that has decided it may send
// without the identity list. Explicit, so nobody reaches it by passing nil.
var None = &List{}

func roleKind(role string) span.Kind {
	switch role {
	case "owner":
		return span.KindOwner
	case "teammate":
		return span.KindTeammate
	}
	return span.KindPerson
}

func literalPattern(text string) string {
	parts := strings.Fields(text)
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return `(?i)` + strings.Join(parts, `[\s\p{Z}\x{85}._-]*`)
}

func usable(rx *regexp.Regexp, literal bool, where string) error {
	if MatchesWithBoundary(rx, "", literal) {
		return &Error{where + " matches empty text, so it would match everywhere"}
	}
	for _, p := range lex.PlaceholderWords {
		if MatchesWithBoundary(rx, p, literal) {
			return &Error{fmt.Sprintf("%s matches the placeholder %s, so every scrubbed record would be refused", where, p)}
		}
	}
	return nil
}

func MatchesWithBoundary(rx *regexp.Regexp, s string, literal bool) bool {
	found := false
	identityMatches(rx, s, literal, func(lo, hi int) { found = true })
	return found
}

// alnumBefore / alnumAfter: a letter or digit in any script (`_` is a boundary).
func alnumBefore(s string, i int) bool {
	if i <= 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsNumber(r) || unicode.Is(unicode.Mn, r)
}

func alnumAfter(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsNumber(r) || unicode.Is(unicode.Mn, r)
}

// identityMatches: every match; a literal only with no letter or digit on either side.
func identityMatches(rx *regexp.Regexp, s string, literal bool, emit func(lo, hi int)) {
	if gate.Off(gate.Denylist) {
		return
	}
	if !literal {
		if s == "" {
			if rx.MatchString("") {
				emit(0, 0)
			}
			return
		}
		for _, m := range rx.FindAllStringIndex(s, -1) {
			if m[1] > m[0] {
				emit(m[0], m[1])
			}
		}
		return
	}
	at := 0
	for at <= len(s) {
		m := rx.FindStringIndex(s[at:])
		if m == nil {
			return
		}
		lo, hi := at+m[0], at+m[1]
		if hi > lo && !alnumBefore(s, lo) && !alnumAfter(s, hi) {
			emit(lo, hi)
			at = hi
			continue
		}
		// Retry one rune later: a shorter or later match may stand.
		_, sz := utf8.DecodeRuneInString(s[lo:])
		if sz == 0 {
			sz = 1
		}
		at = lo + sz
	}
}

// Parse: the secret's payload (JSON) and its version, or a DenylistError.
func Parse(payload []byte, version int) (*List, error) {
	if version < 1 {
		return nil, &Error{"the version must be a whole number of 1 or more"}
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, &Error{"the denylist must be an object with identities and vendors"}
	}
	return parseFields(data, version)
}

func parseFields(data map[string]json.RawMessage, version int) (*List, error) {
	unknown := 0
	for k := range data {
		if k != "identities" && k != "vendors" {
			unknown++
		}
	}
	if unknown > 0 {
		return nil, &Error{fmt.Sprintf("%d unknown key(s): only identities and vendors are allowed", unknown)}
	}
	var ids []json.RawMessage
	var vendors []json.RawMessage
	if json.Unmarshal(data["identities"], &ids) != nil || json.Unmarshal(data["vendors"], &vendors) != nil ||
		data["identities"] == nil || data["vendors"] == nil || bytes.Equal(bytes.TrimSpace(data["identities"]), []byte("null")) ||
		bytes.Equal(bytes.TrimSpace(data["vendors"]), []byte("null")) {
		return nil, &Error{"identities and vendors must both be lists"}
	}
	if len(ids) == 0 {
		return nil, &Error{"no identities: a denylist that names nobody scrubs nobody"}
	}
	d := &List{Version: version}
	for i, raw := range ids {
		where := fmt.Sprintf("identities[%d]", i)
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || entry == nil {
			return nil, &Error{where + " must be an object"}
		}
		extra := 0
		for k := range entry {
			if k != "literal" && k != "regex" && k != "role" {
				extra++
			}
		}
		if extra > 0 {
			return nil, &Error{fmt.Sprintf("%s has %d unknown key(s): only literal, regex and role are allowed", where, extra)}
		}
		_, hasLit := entry["literal"]
		_, hasRx := entry["regex"]
		if hasLit == hasRx {
			return nil, &Error{where + " needs exactly one of literal or regex"}
		}
		var role string
		if json.Unmarshal(entry["role"], &role) != nil || !(role == "owner" || role == "teammate" || role == "person") {
			return nil, &Error{where + " role must be one of owner, teammate, person"}
		}
		kind := "literal"
		if hasRx {
			kind = "regex"
		}
		var value string
		if json.Unmarshal(entry[kind], &value) != nil || strings.TrimSpace(value) == "" {
			return nil, &Error{fmt.Sprintf("%s %s is empty or not text", where, kind)}
		}
		var rx *regexp.Regexp
		if kind == "literal" {
			rx = regexp.MustCompile(literalPattern(value))
		} else {
			var err error
			rx, err = regexp.Compile(`(?i)` + value)
			if err != nil {
				// Never the pattern: the compiler's message can quote it.
				return nil, &Error{where + " regex does not compile"}
			}
		}
		if err := usable(rx, kind == "literal", where); err != nil {
			return nil, err
		}
		d.Identities = append(d.Identities, Identity{fmt.Sprintf("identity[%d]:%s", i, role), rx, kind == "literal", roleKind(role)})
	}
	for j, raw := range vendors {
		where := fmt.Sprintf("vendors[%d]", j)
		var name string
		if json.Unmarshal(raw, &name) != nil || lex.RuneLen(strings.TrimSpace(name)) < minVendorChars {
			return nil, &Error{fmt.Sprintf("%s must be text of at least %d characters", where, minVendorChars)}
		}
		rx := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(strings.TrimSpace(name)))
		if err := usable(rx, false, where); err != nil {
			return nil, err
		}
		d.Vendors = append(d.Vendors, vendor{fmt.Sprintf("vendor[%d]", j), rx})
	}
	return d, nil
}

// Load reads the local copy: the secret's payload plus its `version`.
func Load(path string) (*List, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMissing
		}
		return nil, &Error{"the local denylist is unreadable: OSError"}
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		var anyv any
		if json.Unmarshal(raw, &anyv) == nil {
			return nil, &Error{"the local denylist is not a JSON object"}
		}
		return nil, &Error{"the local denylist is unreadable: JSONDecodeError"}
	}
	if data == nil {
		return nil, &Error{"the local denylist is not a JSON object"}
	}
	version := 0
	// A number, never a string that holds one: `"1"` is a list written wrong, and a wrong list is refused whole.
	if v, ok := data["version"]; ok && !bytes.HasPrefix(bytes.TrimSpace(v), []byte(`"`)) {
		var n json.Number
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.UseNumber()
		if dec.Decode(&n) == nil {
			if iv, err := n.Int64(); err == nil && !strings.ContainsAny(n.String(), ".eE") {
				version = int(iv)
			}
		}
		delete(data, "version")
	}
	if version < 1 {
		return nil, &Error{"the version must be a whole number of 1 or more"}
	}
	return parseFields(data, version)
}

func (d *List) Apply(s string, out *span.Set) {
	if d == nil || gate.Off(gate.Denylist) {
		return
	}
	for _, id := range d.Identities {
		identityMatches(id.Rx, s, id.Literal, func(lo, hi int) { out.Add(lo, hi, id.kind) })
	}
	for _, v := range d.Vendors {
		for _, m := range v.Rx.FindAllStringIndex(s, -1) {
			out.Add(m[0], m[1], span.KindVendor)
		}
	}
}
