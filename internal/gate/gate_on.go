//go:build scrubgate

package gate

import (
	"os"
	"strings"
)

// The gate's build only (`-tags scrubgate`): SCRUB_GATE_OFF names detectors to turn off, as a
// bug inside each would, so the gate can show the audit still refuses what that detector hides
// (contract rule 9), and `converge` makes every re-read find more, so it can show the bounded
// rounds fail closed (rule 8).
var gateOff = func() map[string]bool {
	m := map[string]bool{}
	for _, name := range strings.Split(os.Getenv("SCRUB_GATE_OFF"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			m[name] = true
		}
	}
	return m
}()

func Off(name string) bool { return gateOff[name] }
