//go:build linux

package monitor

import (
	"runtime"
	"testing"
)

func TestAuditArch(t *testing.T) {
	if _, ok := auditArch(); !ok {
		t.Errorf("%s: no seccomp audit arch", runtime.GOARCH)
	}
}

func TestSocketcallArgsUnknown(t *testing.T) {
	if _, _, ok := socketcallArgs(0, [6]uint64{1}); ok { // SYS_SOCKET: not asked about
		t.Error("socket(2) via socketcall: want not ok")
	}
}
