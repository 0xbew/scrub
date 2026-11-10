package detect

import (
	"github.com/0xbew/scrub/internal/gate"
	"github.com/0xbew/scrub/internal/lex"
	"github.com/0xbew/scrub/internal/span"
)

// Detector is one root rule run over a reading, under the name the gate's build turns it off by.
type Detector struct {
	Name string
	run  func(*Scan)
}

// Secrets: the secret detectors, in the order they run on every reading.
var Secrets = []Detector{
	{gate.Named, (*Scan).named},
	{gate.Heredoc, (*Scan).heredocs},
	{gate.Colon, (*Scan).colon},
	{gate.Flags, (*Scan).flags},
	{gate.Options, (*Scan).programOptions},
	{gate.Headers, (*Scan).headers},
	{gate.Bearer, (*Scan).bearer},
	{gate.Userinfo, (*Scan).userinfo},
	{gate.Netrc, (*Scan).netrc},
	{gate.Quoted, (*Scan).quotedAssignments},
	{gate.Tokens, (*Scan).tokens},
	{gate.Code, func(c *Scan) {
		if !c.R.Pct {
			c.code()
		}
	}},
}

// Runs: JWTs and long runs, in this order, on every reading that is not joined (a `\n` read as a
// letter glues words into a run that is not one).
var Runs = []Detector{
	{gate.JWT, (*Scan).jwt},
	{gate.Long, (*Scan).longRuns},
}

// Run runs each detector of list over c's reading, in order, skipping one the gate's build turned off.
func Run(list []Detector, c *Scan) {
	for _, d := range list {
		if !gate.Off(d.Name) {
			d.run(c)
		}
	}
}

// heredocs hides the body of each heredoc that opens a credential's value.
func (c *Scan) heredocs() {
	HeredocValues(c.S, func(lo, hi int) {
		if lo < hi && !lex.OnlyPlaceholders(c.S[lo:hi]) {
			c.Hide(lo, hi, span.KindSecret)
		}
	})
}
