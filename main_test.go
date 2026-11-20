package main

import (
	"slices"
	"testing"
)

func TestParseArgs(t *testing.T) {
	const home = "/home/u"
	const def = "/home/u/.config/ssh-agent-keeper/ssh-agent-pid"
	for _, tc := range []struct {
		args []string
		want options
	}{
		{nil, options{pidFile: def}},
		{[]string{"-f", "/x/pid"}, options{pidFile: "/x/pid"}},
		{[]string{"--pid-file=~/.ssh-agent"}, options{pidFile: "/home/u/.ssh-agent"}},
		{[]string{"-k", "/k/a"}, options{pidFile: def, keys: []string{"/k/a"}}},
		{[]string{"-k", "~/.ssh/a", "--key=~/.ssh/b", "-f", "/x/pid", "--key", "/k/c"},
			options{pidFile: "/x/pid", keys: []string{"/home/u/.ssh/a", "/home/u/.ssh/b", "/k/c"}}},
	} {
		got, err := parseArgs(tc.args, home)
		if err != nil {
			t.Errorf("parseArgs(%q): %v", tc.args, err)
			continue
		}
		if got.pidFile != tc.want.pidFile || !slices.Equal(got.keys, tc.want.keys) {
			t.Errorf("parseArgs(%q) = %+v, want %+v", tc.args, got, tc.want)
		}
	}

	for _, bad := range [][]string{{"/k/a"}, {"-t", "8h"}, {"-k"}} {
		if _, err := parseArgs(bad, home); err == nil {
			t.Errorf("parseArgs(%q) succeeded, want error", bad)
		}
	}
}
