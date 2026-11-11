// Command scrub reads JSONL requests on stdin and writes one JSON line per request:
//
//	scrub [--denylist PATH] < requests.jsonl
//
// Request:  {"op": "scrub"|"scrub_diff"|"redact"|"audit_text"|"audit_body", "text": str, "limit": int}
// Response: {"out": str} for scrub, scrub_diff and redact; {"hits": [rule ids]} for the audits
// (audit_body reads text's UTF-8 bytes as a JSON body).
//
// A request that cannot be answered (a line that is not JSON, an unknown op) gets a line with an
// "error" key and, so that a caller reading only "out" or "hits" cannot take it for a clean answer,
// the refusal both would carry: "out" is the cut marker and "hits" is ["unreadable"].
//
// A denylist that cannot be used is one such line with "denylist_error" in place of "error", and no
// request is answered. The reason never quotes an entry or a path.
//
// Exit status: 0 when every request was answered, 1 when the denylist cannot be used or reading
// requests or writing answers failed (answers may be missing), 2 on a usage error.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/0xbew/scrub"
)

const defaultLimit = 4000

type request struct {
	Op    string `json:"op"`
	Text  string `json:"text"`
	Limit *int   `json:"limit"`
}

type outResponse struct {
	Out string `json:"out"`
}

type hitsResponse struct {
	Hits []string `json:"hits"`
}

// refusal answers a request that was not answered: it carries what a refused scrub and a refused audit carry.
type refusal struct {
	Error     string   `json:"error,omitempty"`
	UnknownOp *string  `json:"unknown_op,omitempty"`
	Denylist  string   `json:"denylist_error,omitempty"`
	Out       string   `json:"out"`
	Hits      []string `json:"hits"`
}

func newRefusal(reason string) refusal {
	return refusal{Error: reason, Out: scrub.Cut, Hits: []string{"unreadable"}}
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
				return denylistFailed(err, stdout, stderr)
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
	return serve(stdin, stdout, stderr, d)
}

// denylistFailed reports a denylist that cannot be used as the only line of output.
func denylistFailed(err error, stdout, stderr io.Writer) int {
	var de *scrub.DenylistError
	msg := "DenylistError: the denylist cannot be used"
	if errors.As(err, &de) {
		msg = "DenylistError: " + de.Error()
	}
	res := newRefusal("")
	res.Denylist = msg
	if werr := json.NewEncoder(stdout).Encode(res); werr != nil {
		fmt.Fprintln(stderr, "scrub: cannot write the denylist error:", werr)
	}
	return 1
}

// serve answers each request line until stdin ends. A read or write failure stops it with status 1.
func serve(stdin io.Reader, stdout, stderr io.Writer, d *scrub.Denylist) int {
	in := bufio.NewReader(stdin)
	out := bufio.NewWriter(stdout)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for {
		line, readErr := in.ReadBytes('\n')
		if len(trimSpace(line)) > 0 {
			if err := enc.Encode(answer(line, d, stderr)); err != nil {
				fmt.Fprintln(stderr, "scrub: cannot write an answer:", err)
				return 1
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			fmt.Fprintln(stderr, "scrub: cannot read requests:", readErr)
			_ = out.Flush() // the answers already made; the status says the input was cut short
			return 1
		}
	}
	if err := out.Flush(); err != nil {
		fmt.Fprintln(stderr, "scrub: cannot write the last answers:", err)
		return 1
	}
	return 0
}

func answer(line []byte, d *scrub.Denylist, stderr io.Writer) any {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return newRefusal("unreadable request")
	}
	limit := defaultLimit
	if req.Limit != nil {
		limit = *req.Limit
	}
	return handle(req, d, limit, stderr)
}

// handle answers one request. A panic fails closed: nothing of the text is sent, and an
// audit refuses. The panic is noted on stderr without the request's text.
func handle(req request, d *scrub.Denylist, limit int, stderr io.Writer) (res any) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "scrub: internal error on op %q: %v\n", req.Op, r)
			if req.Op == "audit_text" || req.Op == "audit_body" {
				res = hitsResponse{Hits: []string{"unreadable"}}
			} else {
				res = outResponse{Out: cutFor(limit)}
			}
		}
	}()
	switch req.Op {
	case "scrub":
		return outResponse{Out: scrub.Scrub(req.Text, d, limit)}
	case "scrub_diff":
		return outResponse{Out: scrub.ScrubDiff(req.Text, d, limit)}
	case "redact":
		return outResponse{Out: scrub.Redact(req.Text, limit)}
	case "audit_text":
		return hitsResponse{Hits: nonNil(scrub.Audit(req.Text, d))}
	case "audit_body":
		return hitsResponse{Hits: nonNil(scrub.AuditBody([]byte(req.Text), d))}
	}
	res = newRefusal("unknown op")
	r := res.(refusal)
	r.UnknownOp = &req.Op
	return r
}

// cutFor is what a failed scrub sends: the cut marker, or nothing when the limit is shorter than it.
func cutFor(limit int) string {
	if utf8.RuneCountInString(scrub.Cut) > limit {
		return ""
	}
	return scrub.Cut
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
