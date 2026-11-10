//go:build !scrubgate

package scrub

// off is always false in a release build: no switch can turn a detector off.
func off(string) bool { return false }
