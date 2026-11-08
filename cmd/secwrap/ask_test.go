package main

import (
	"strings"
	"testing"
)

func TestPromptNetwork(t *testing.T) {
	it := webItem{ID: 1, PID: 42, Comm: "curl", Kind: "connect", Proto: "tcp", Remote: "93.184.215.14:443"}
	for _, tc := range []struct {
		lines       []string
		allow, host bool
		out         string // in the output
	}{
		{[]string{"y"}, true, false, "[y/N/a/d/?]"},
		{[]string{""}, false, false, ""},
		{[]string{"a"}, true, true, ""},
		{[]string{"d"}, false, true, ""},
		{[]string{"?", "a"}, true, true, "a: allow this IP, d: disallow this IP"},
		{[]string{"x", "n"}, false, false, "answer y, n, a or d (? for help)"},
	} {
		var w strings.Builder
		lines := tc.lines
		read := func() (string, readResult) {
			l := lines[0]
			lines = lines[1:]
			return l, gotLine
		}
		af, r := prompt(&w, it, read, false)
		if r != gotLine || af == nil || *af.Allow != tc.allow || af.Host != tc.host {
			t.Errorf("%q: got %+v, %v; want allow=%v host=%v", tc.lines, af, r, tc.allow, tc.host)
		}
		if !strings.Contains(w.String(), tc.out) {
			t.Errorf("%q: output %q lacks %q", tc.lines, w.String(), tc.out)
		}
		if strings.Contains(w.String(), "any port on this IP") {
			t.Errorf("%q: the question still explains Y/D", tc.lines)
		}
	}
}
