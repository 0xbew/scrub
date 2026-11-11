package scrub

import (
	"slices"

	"github.com/0xbew/scrub/internal/vocab"
)

// CodeOwners returns the words after which `code` holds a credential (mfa_code, backup_code).
// The rules are fixed when the package loads, so the copy is for reading only.
func CodeOwners() []string { return slices.Clone(vocab.CodeOwners) }

// KeyOwners returns the words that own a `key` (api_key, ssh_key). The rules are fixed when
// the package loads, so the copy is for reading only.
func KeyOwners() []string { return slices.Clone(vocab.KeyOwners) }

// IsCredentialName reports whether a NAME in `NAME=value`, `"name": value` or `name: value`
// holds a credential.
func IsCredentialName(name string) bool { return vocab.IsCredentialName(name) }

// LooksSecret reports whether a value with no name to vouch for it is random-looking text
// of 16 or more characters.
func LooksSecret(value string) bool { return vocab.LooksSecret(value) }

// IsIdentifier reports whether a long run is lowercase words joined by `_`
// (`test_a_401_stops_the_run_instead_of_marching_on`).
func IsIdentifier(run string) bool { return vocab.IsIdentifier(run) }
