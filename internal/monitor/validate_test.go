package monitor

import (
	"context"
	"strings"
	"testing"
)

func TestValidateAllowAsk(t *testing.T) {
	ask := func(context.Context, AskRequest) AskAnswer { return AskAnswer{} }
	cases := []struct {
		name string
		o    Options
		want string // substring of the error, "" for no error
	}{
		{"attach ask without allow-ask", Options{
			PIDs: []int{1}, Files: true, FilesAction: ActionAsk, Ask: ask,
		}, "allow-ask"},
		{"attach ask with allow-ask", Options{
			PIDs: []int{1}, Files: true, FilesAction: ActionAsk, Ask: ask, AllowAsk: true,
		}, ""},
		{"ask with --all", Options{
			All: true, Files: true, FilesAction: ActionAsk, Ask: ask,
		}, "--all"},
		{"allow-ask without attach", Options{
			Command: []string{"true"}, Files: true, FilesAction: ActionAsk, Ask: ask, AllowAsk: true,
		}, "only applies when attaching"},
		{"launched ask stays fine", Options{
			Command: []string{"true"}, Files: true, FilesAction: ActionAsk, Ask: ask,
		}, ""},
	}
	for _, c := range cases {
		err := c.o.Validate()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
}
