package scrub

import "github.com/0xbew/scrub/internal/audit"

// Hit is an audit rule id. The audit returns rule ids, never the text it found.
type Hit = string

// Audit returns the rule ids that fire anywhere in text, or `unreadable` for text over
// MaxAuditBytes.
func Audit(text string, d *Denylist) []Hit { return audit.Audit(text, d.list()) }

// MaxAuditBytes is the most text one audit reads, a body or all the strings of a value
// together. More is refused as `unreadable`, never audited in part.
const MaxAuditBytes = audit.MaxBytes

// AuditValue: Audit over every string in a JSON-shaped value, keys included. A value of any
// other Go type (map[string]string, []string, a struct) is read as its JSON encoding; one
// with no JSON encoding is `unreadable`.
func AuditValue(v any, d *Denylist) []Hit { return audit.AuditValue(v, d.list()) }

// AuditBody: Audit over a JSON document or JSON lines, decoded as the receiver reads them. A
// body that cannot be decoded, or is over MaxAuditBytes, is `unreadable`: it cannot be shown clean.
func AuditBody(body []byte, d *Denylist) []Hit { return audit.AuditBody(body, d.list()) }
