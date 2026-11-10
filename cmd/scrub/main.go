// Command scrub reads JSONL requests on stdin and writes one JSON line per request:
//
//	scrub [--denylist PATH] < requests.jsonl
//
// Request:  {"op": "scrub"|"scrub_diff"|"redact"|"audit_text"|"audit_body", "text": str, "limit": int}
// Response: {"out": str} for scrub, scrub_diff and redact; {"hits": [rule ids]} for the audits
// (audit_body reads text's UTF-8 bytes as a JSON body). A denylist that cannot be used is one
// line {"denylist_error": "<reason>"} and exit 0; the reason never quotes an entry or a path.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/0xbew/scrub"
)

const defaultLimit = 4000

type request struct {
	Op    string `json:"op"`
	Text  string `json:"text"`
	Limit *int   `json:"limit"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	d := scrub.NoDenylist
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--denylist":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "usage: scrub [--denylist PATH] < requests.jsonl")
				return 2
			}
			loaded, err := scrub.LoadDenylist(args[i+1])
			if err != nil {
				var de *scrub.DenylistError
				msg := "DenylistError: the denylist cannot be used"
				if errors.As(err, &de) {
					msg = "DenylistError: " + de.Error()
				}
				line, _ := json.Marshal(map[string]string{"denylist_error": msg})
				fmt.Fprintln(stdout, string(line))
				return 0
			}
			d = loaded
			i++
		case "--version":
			fmt.Fprintf(stdout, "scrub %d\n", scrub.Version)
			return 0
		default:
			fmt.Fprintln(stderr, "usage: scrub [--denylist PATH] < requests.jsonl")
			return 2
		}
	}
	in := bufio.NewReader(stdin)
	out := bufio.NewWriter(stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for {
		line, err := in.ReadBytes('\n')
		if len(line) > 0 && len(trimSpace(line)) > 0 {
			var req request
			if jerr := json.Unmarshal(line, &req); jerr != nil {
				_ = enc.Encode(map[string]string{"error": "unreadable request"})
			} else {
				limit := defaultLimit
				if req.Limit != nil {
					limit = *req.Limit
				}
				_ = enc.Encode(handle(req, d, limit))
			}
		}
		if err != nil {
			break
		}
	}
	return 0
}

// handle answers one request. A panic fails closed: nothing of the text is sent, and an
// audit refuses.
func handle(req request, d *scrub.Denylist, limit int) (res any) {
	defer func() {
		if recover() != nil {
			if req.Op == "audit_text" || req.Op == "audit_body" {
				res = map[string][]string{"hits": {"unreadable"}}
			} else {
				res = map[string]string{"out": scrub.Cut}
			}
		}
	}()
	switch req.Op {
	case "scrub":
		return map[string]string{"out": scrub.Scrub(req.Text, d, limit)}
	case "scrub_diff":
		return map[string]string{"out": scrub.ScrubDiff(req.Text, d, limit)}
	case "redact":
		return map[string]string{"out": scrub.Redact(req.Text, limit)}
	case "audit_text":
		return map[string][]string{"hits": nonNil(scrub.Audit(req.Text, d))}
	case "audit_body":
		return map[string][]string{"hits": nonNil(scrub.AuditBody([]byte(req.Text), d))}
	}
	return map[string]string{"unknown_op": req.Op}
}

func nonNil(h []string) []string {
	if h == nil {
		return []string{}
	}
	return h
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\n' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}
