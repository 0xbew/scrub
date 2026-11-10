package span

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

type Set struct{ Spans []Span }

func (o *Set) Add(lo, hi int, k Kind) {
	if lo < hi {
		o.Spans = append(o.Spans, Span{lo, hi, k})
	}
}
