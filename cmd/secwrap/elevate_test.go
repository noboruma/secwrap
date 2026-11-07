package main

import "testing"

func TestNeedsRoot(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"monitor", "--net", "--", "curl", "-h"}, true}, // -h after -- is the command's
		{[]string{"monitor", "-h"}, false},
		{[]string{"shell"}, true},
		{[]string{"attach", "--name", "nginx"}, true},
		{[]string{"session", "attach"}, true},
		{[]string{"session", "list"}, false},
		{[]string{"session"}, false},
		{[]string{"sbom", "/bin/ls"}, false},
	} {
		if got := needsRoot(c.args); got != c.want {
			t.Errorf("needsRoot(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}
