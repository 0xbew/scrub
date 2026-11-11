package scrub

import (
	"errors"

	"github.com/0xbew/scrub/internal/denylist"
)

// DenylistError: the denylist cannot be used. The message never quotes an entry or a path.
type DenylistError struct{ msg string }

func (e *DenylistError) Error() string { return e.msg }

// ErrDenylistMissing: there is no local copy. Compare with errors.Is; do not reassign it.
var ErrDenylistMissing = &DenylistError{"no local denylist"}

// Denylist is a compiled identity and vendor list, applied whole or refused whole.
type Denylist struct {
	Version  int
	compiled *denylist.List
}

// NoDenylist: the shapes and secrets only, for a sender that has decided it may send
// without the identity list. Explicit, so nobody reaches it by passing nil.
var NoDenylist = &Denylist{}

// list: the compiled list the internals read. nil stays nil (no denylist: nothing is sent); a
// Denylist with no compiled list, as NoDenylist, is an empty one.
func (d *Denylist) list() *denylist.List {
	if d == nil {
		return nil
	}
	if d.compiled == nil {
		return denylist.None
	}
	return d.compiled
}

func wrap(l *denylist.List, err error) (*Denylist, error) {
	if err != nil {
		if errors.Is(err, denylist.ErrMissing) {
			return nil, ErrDenylistMissing
		}
		var e *denylist.Error
		if errors.As(err, &e) {
			return nil, &DenylistError{e.Error()}
		}
		return nil, err
	}
	return &Denylist{Version: l.Version, compiled: l}, nil
}

// ParseDenylist: the secret's payload (JSON) and its version, or a DenylistError.
func ParseDenylist(payload []byte, version int) (*Denylist, error) {
	return wrap(denylist.Parse(payload, version))
}

// LoadDenylist reads the local copy: the secret's payload plus its `version`.
func LoadDenylist(path string) (*Denylist, error) { return wrap(denylist.Load(path)) }
