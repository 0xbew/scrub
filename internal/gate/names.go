package gate

// The switches the gate's build turns off by name (SCRUB_GATE_OFF, -tags scrubgate). A detector in
// detect's registry is switched there by its entry's name; one whose code the audit also reads checks
// its switch inside that code, so the audit's reading goes blind with it (contract rule 9 measures
// that the audit still refuses what such a detector hides).
const (
	Named    = "named"
	Heredoc  = "heredoc"
	Colon    = "colon"
	Flags    = "flags"
	Options  = "options"
	Headers  = "headers"
	Bearer   = "bearer"
	Userinfo = "userinfo"
	Netrc    = "netrc"
	Quoted   = "quoted"
	Tokens   = "tokens"
	Code     = "code"
	JWT      = "jwt"
	Long     = "long"
	Email    = "email"
	Phone    = "phone"
	Denylist = "denylist"
	// The pipeline's own: the re-read's audit pass (rule 9), and re-reads that never hold still (rule 8).
	RereadAudit = "reread-audit"
	Converge    = "converge"
)
