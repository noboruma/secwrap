package main

import (
	"fmt"
	"io"
	"os"

	"github.com/noboruma/secwrap/internal/monitor"
)

// cmdCap prints what this kernel lets secwrap do. No root needed.
func cmdCap(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: secwrap cap")
	}
	printCaps(os.Stdout, monitor.ProbeCaps())
	return nil
}

func printCaps(w io.Writer, c monitor.Caps) {
	fmt.Fprintf(w, "Linux %s (%s)\n", c.Kernel, c.Machine)
	line := func(name, what, why string) {
		if why == "" {
			fmt.Fprintf(w, "  %-11s %s\n", name, what)
			return
		}
		fmt.Fprintf(w, "  %-11s %-13s (%s)\n", name, what, why)
	}
	net, files := c.Net(), c.Files()
	line("network", net.String(), net.Why)
	line("filesystem", files.String(), files.Why)
	line("exec", files.String(), files.Why)
	if files.Log {
		line("sbom", "yes", "")
	} else {
		line("sbom", "unavailable", files.Why)
	}
}
