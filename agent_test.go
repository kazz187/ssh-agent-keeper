package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fswatcher/fswatcher"
)

func TestParseAgentEnv(t *testing.T) {
	out := "SSH_AUTH_SOCK=/tmp/ssh-XXXXabcd/agent.123; export SSH_AUTH_SOCK;\n" +
		"SSH_AGENT_PID=124; export SSH_AGENT_PID;\n" +
		"echo Agent pid 124;\n"
	a, err := parseAgentEnv([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	want := Agent{Sock: "/tmp/ssh-XXXXabcd/agent.123", PID: 124}
	if a != want {
		t.Errorf("got %+v, want %+v", a, want)
	}
	if got := string(a.stateFormat()); got != out {
		t.Errorf("stateFormat:\n%s\nwant:\n%s", got, out)
	}

	for _, bad := range []string{"", "SSH_AUTH_SOCK=/x;\n", "SSH_AUTH_SOCK=/x;\nSSH_AGENT_PID=abc;\n"} {
		if _, err := parseAgentEnv([]byte(bad)); err == nil {
			t.Errorf("parseAgentEnv(%q) succeeded, want error", bad)
		}
	}
}

func TestShellExports(t *testing.T) {
	a := Agent{Sock: `/tmp/it's a "dir" $HOME/agent.1`, PID: 42}
	out, err := exec.Command("sh", "-c", a.shellExports()+`printf '%s\n%s' "$SSH_AUTH_SOCK" "$SSH_AGENT_PID"`).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := a.Sock + "\n42"; string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// requireAgent skips the test when ssh-agent is not available.
func requireAgent(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent not found")
	}
}

// ensureAgentT calls ensureAgent and kills the agent when the test ends.
func ensureAgentT(t *testing.T, path string) Agent {
	t.Helper()
	a, err := ensureAgent(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(a.PID, syscall.SIGTERM) })
	return a
}

func TestEnsureAgent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-agent")
	requireAgent(t)

	first := ensureAgentT(t, path)
	if !first.alive() {
		t.Fatalf("started agent %+v is not alive", first)
	}
	if n, err := first.countIdentities(); err != nil || n != 0 {
		t.Errorf("countIdentities = %d, %v; want 0, nil", n, err)
	}
	if b, _ := os.ReadFile(path); string(b) != string(first.stateFormat()) {
		t.Errorf("state file = %q, want %q", b, first.stateFormat())
	}

	t.Run("reuses running agent", func(t *testing.T) {
		again := ensureAgentT(t, path)
		if again != first {
			t.Errorf("got %+v, want the running %+v", again, first)
		}
	})

	t.Run("restarts dead agent", func(t *testing.T) {
		if err := syscall.Kill(first.PID, syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		waitDead(t, first)
		next := ensureAgentT(t, path)
		if next == first || !next.alive() {
			t.Errorf("got %+v, want a new live agent", next)
		}
	})

	t.Run("ignores reused pid", func(t *testing.T) {
		// A live process that is not the agent, as after a reboot.
		stale := Agent{Sock: filepath.Join(t.TempDir(), "gone"), PID: os.Getpid()}
		if err := os.WriteFile(path, stale.stateFormat(), 0o600); err != nil {
			t.Fatal(err)
		}
		next := ensureAgentT(t, path)
		if next == stale || !next.alive() {
			t.Errorf("got %+v, want a new live agent", next)
		}
	})
}

func TestAnnounceWakesWatchers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-agent")
	a := Agent{Sock: "/tmp/agent.1", PID: 1}
	if err := os.WriteFile(path, a.stateFormat(), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := fswatcher.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Add(path, fswatcher.All); err != nil {
		t.Fatal(err)
	}

	if err := announce(path, a); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.Events:
	case <-time.After(5 * time.Second):
		t.Fatal("no event after announce")
	}
	if b, _ := os.ReadFile(path); string(b) != string(a.stateFormat()) {
		t.Errorf("state file changed to %q", b)
	}

	// An announcement for an agent that is no longer recorded is dropped.
	other := Agent{Sock: "/tmp/agent.2", PID: 2}
	if err := announce(path, other); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), a.Sock) {
		t.Errorf("state file overwritten with %q", b)
	}
}

func waitDead(t *testing.T, a Agent) {
	t.Helper()
	for range 100 {
		if !a.alive() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("agent %+v did not exit", a)
}
