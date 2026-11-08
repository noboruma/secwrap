//go:build linux

package monitor

import (
	"reflect"
	"syscall"
	"testing"
)

func TestCredArgRoundTrip(t *testing.T) {
	for _, cred := range []*syscall.Credential{
		nil,
		{Uid: 1000, Gid: 1000},
		{Uid: 1000, Gid: 100, Groups: []uint32{27, 100, 4294967294}},
	} {
		got, err := parseCredArg(credArg(cred))
		if err != nil {
			t.Fatalf("%v: %v", cred, err)
		}
		if !reflect.DeepEqual(got, cred) {
			t.Errorf("round trip: got %+v, want %+v", got, cred)
		}
	}
	for _, bad := range []string{"", "1000", "1000:x:", "1000:1000:a", "-1:0:"} {
		if _, err := parseCredArg(bad); err == nil {
			t.Errorf("parseCredArg(%q) accepted", bad)
		}
	}
}
