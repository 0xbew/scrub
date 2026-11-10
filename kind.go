package scrub

import "github.com/0xbew/scrub/internal/span"

// Kind is what a hidden span becomes when it is rendered.
type Kind uint8

const (
	KindSecret Kind = iota
	KindLong
	KindJWT
	KindEmail
	KindPhone
	KindOwner
	KindTeammate
	KindPerson
	KindVendor
)

// Span is a hidden range of the source text, in byte offsets.
type Span struct {
	Lo, Hi int
	Kind   Kind
}

// The internals' kinds are numbered as these; a duplicate map key fails the build if they differ.
var _ = map[bool]int{false: 0, KindSecret == Kind(span.KindSecret) && KindLong == Kind(span.KindLong) &&
	KindJWT == Kind(span.KindJWT) && KindEmail == Kind(span.KindEmail) && KindPhone == Kind(span.KindPhone) &&
	KindOwner == Kind(span.KindOwner) && KindTeammate == Kind(span.KindTeammate) &&
	KindPerson == Kind(span.KindPerson) && KindVendor == Kind(span.KindVendor): 1}
