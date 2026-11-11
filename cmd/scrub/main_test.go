package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// A request the CLI cannot answer must never read as a clean one: "hits" absent was "no hits".
func TestUnanswerableRequestsRefuse(t *testing.T) {
	cases := []struct{ name, line, want string }{
		{"not JSON", "{oops", `{"error":"unreadable request","out":"…[cut]","hits":["unreadable"]}`},
		{"unknown op", `{"op":"audit","text":"x"}`, `{"error":"unknown op","unknown_op":"audit","out":"…[cut]","hits":["unreadable"]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(nil, strings.NewReader(c.line+"\n"), &out, &errOut); code != 0 {
				t.Errorf("exit %d, want 0 (every request was answered)", code)
			}
			if got := strings.TrimSpace(out.String()); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

// Lost output and a denylist that cannot load must show in the exit status.
func TestFailuresExitNonZero(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--denylist", "/nonexistent/denylist.json"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Errorf("missing denylist: exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), `"denylist_error"`) {
		t.Errorf("missing denylist: no denylist_error line in %q", out.String())
	}
	if code := run(nil, strings.NewReader(`{"op":"redact","text":"hi"}`+"\n"), failingWriter{}, &errOut); code != 1 {
		t.Errorf("write failure: exit %d, want 1", code)
	}
}
