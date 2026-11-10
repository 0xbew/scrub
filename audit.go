package scrub

import "github.com/0xbew/scrub/internal/audit"

// Hit is an audit rule id. The audit returns rule ids, never the text it found.
type Hit = string

// Audit returns the rule ids that fire anywhere in text.
func Audit(text string, d *Denylist) []Hit { return audit.Audit(text, d.list()) }

// AuditValue: Audit over every string in a JSON-shaped value, keys included.
func AuditValue(v any, d *Denylist) []Hit { return audit.AuditValue(v, d.list()) }

// AuditBody: Audit over a JSON document or JSON lines, decoded as the receiver reads them. A
// body that cannot be decoded is `unreadable`: it cannot be shown clean.
func AuditBody(body []byte, d *Denylist) []Hit { return audit.AuditBody(body, d.list()) }
