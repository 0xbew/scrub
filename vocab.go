package scrub

import "github.com/0xbew/scrub/internal/vocab"

// CodeOwners: `code` holds a credential only after one of these (mfa_code, backup_code).
var CodeOwners = vocab.CodeOwners

// KeyOwners: a word that owns a `key` (api_key, ssh_key).
var KeyOwners = vocab.KeyOwners

// IsCredentialName reports whether a NAME in `NAME=value`, `"name": value` or `name: value`
// holds a credential.
func IsCredentialName(name string) bool { return vocab.IsCredentialName(name) }

// LooksSecret reports whether a value with no name to vouch for it is random-looking text
// of 16 or more characters.
func LooksSecret(value string) bool { return vocab.LooksSecret(value) }

// IsIdentifier reports whether a long run is lowercase words joined by `_`
// (`test_a_401_stops_the_run_instead_of_marching_on`).
func IsIdentifier(run string) bool { return vocab.IsIdentifier(run) }
