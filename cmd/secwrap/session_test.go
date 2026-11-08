package main

import (
	"flag"
	"strings"
	"testing"

	"github.com/noboruma/secwrap/internal/monitor"
)

func TestBareMode(t *testing.T) {
	for _, tc := range []struct {
		withAsk bool // monitor, run, shell (false: attach)
		all     bool // monitor --all
		args    string
		net     monitor.Action
	}{
		{true, false, "--net", monitor.ActionAsk},
		{true, false, "--net --deny-all", monitor.ActionDeny},
		{true, false, "--net --log-only", monitor.ActionLog},
		{true, false, "--net ask --log-only", monitor.ActionAsk},
		{true, false, "--net ask --deny-all", monitor.ActionAsk},
		{true, false, "--net log", monitor.ActionLog},
		{true, false, "--net deny", monitor.ActionDeny},
		{true, true, "--net", monitor.ActionLog},
		{true, true, "--net --deny-all", monitor.ActionDeny},
		{true, true, "--net ask", monitor.ActionAsk}, // refused later, saying why
		{false, false, "--net", monitor.ActionLog},
		{false, false, "--net --deny-all", monitor.ActionDeny},
		{false, false, "--net ask", monitor.ActionAsk}, // refused later, saying why
	} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		s := newSession(fs, tc.withAsk)
		parseFlags(fs, append(strings.Fields(tc.args), "--", "true"))
		s.resolve()
		if tc.all {
			s.bareLog()
		}
		if !s.net.on || s.net.act != tc.net {
			t.Errorf("withAsk=%v all=%v %q: net on=%v %v, want %v", tc.withAsk, tc.all, tc.args, s.net.on, s.net.act, tc.net)
		}
	}
}

func TestDefaults(t *testing.T) {
	A, L, D, off := monitor.ActionAsk, monitor.ActionLog, monitor.ActionDeny, monitor.Action(200) // off: not watched
	for _, tc := range []struct {
		withAsk          bool
		args             string
		net, files, exec monitor.Action
	}{
		{true, "", A, A, A},
		{true, "--net log", L, A, A},
		{true, "--net", A, A, A},
		{true, "--deny-all", D, D, D},
		{true, "--log-only", L, L, L},
		{true, "--log-only --net ask", A, L, L},
		{false, "--deny-all", D, D, D},
		{true, "--net deny --fs off --exec off", D, off, off},
		{true, "--exec off", A, A, off},
		{false, "", L, L, L},
		{false, "--net deny --fs off --exec off", D, off, off},
	} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		s := newSession(fs, tc.withAsk)
		parseFlags(fs, append(strings.Fields(tc.args), "--", "true"))
		s.resolve()
		for _, c := range []struct {
			name string
			got  category
			want monitor.Action
		}{{"net", s.net, tc.net}, {"fs", s.files, tc.files}, {"exec", s.exec, tc.exec}} {
			if c.want == off {
				if c.got.on {
					t.Errorf("withAsk=%v %q: %s on (%v), want off", tc.withAsk, tc.args, c.name, c.got.act)
				}
			} else if !c.got.on || c.got.act != c.want {
				t.Errorf("withAsk=%v %q: %s on=%v %v, want %v", tc.withAsk, tc.args, c.name, c.got.on, c.got.act, c.want)
			}
		}
	}
}
