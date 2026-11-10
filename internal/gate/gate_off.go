//go:build !scrubgate

package gate

// Off is always false in a release build: no switch can turn a detector off.
func Off(string) bool { return false }
