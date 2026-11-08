package main

import (
	"os"
	"testing"
)

func TestNeedsRoot(t *testing.T) {
	tty := false
	stdinTTY = func() bool { return tty }
	defer func() { stdinTTY = func() bool { return isTerminal(os.Stdin) } }()
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"monitor", "--net", "--", "curl", "-h"}, true}, // -h after -- is the command's
		{[]string{"monitor", "-h"}, false},
		{[]string{"shell"}, true},
		{[]string{"attach", "--name", "nginx"}, true},
		{[]string{"sessions", "attach"}, true},
		{[]string{"sessions", "list"}, false},
		{[]string{"sessions"}, false},
		{[]string{"sbom", "/bin/ls"}, false},
	} {
		if got := needsRoot(c.args); got != c.want {
			t.Errorf("needsRoot(%q) = %v, want %v", c.args, got, c.want)
		}
	}
	tty = true
	if !needsRoot([]string{"sessions"}) {
		t.Error("needsRoot(session) in a terminal = false: the UI serves the web page")
	}
	if needsRoot([]string{"sessions", "list"}) {
		t.Error("needsRoot(session list) in a terminal = true")
	}
}
