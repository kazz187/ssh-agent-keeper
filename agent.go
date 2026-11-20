package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Agent identifies a running ssh-agent by the two values ssh-agent itself
// exports.
type Agent struct {
	Sock string // SSH_AUTH_SOCK
	PID  int    // SSH_AGENT_PID
}

var envRe = regexp.MustCompile(`(?m)^\s*(SSH_AUTH_SOCK|SSH_AGENT_PID)=([^;\n]*)`)

// parseAgentEnv extracts the agent from shell code in the format printed by
// `ssh-agent -s`.
func parseAgentEnv(b []byte) (Agent, error) {
	var a Agent
	for _, m := range envRe.FindAllSubmatch(b, -1) {
		v := strings.Trim(string(m[2]), `"'`)
		switch string(m[1]) {
		case "SSH_AUTH_SOCK":
			a.Sock = v
		case "SSH_AGENT_PID":
			pid, err := strconv.Atoi(v)
			if err != nil {
				return Agent{}, fmt.Errorf("invalid SSH_AGENT_PID %q", v)
			}
			a.PID = pid
		}
	}
	if a.Sock == "" || a.PID <= 0 {
		return Agent{}, errors.New("SSH_AUTH_SOCK or SSH_AGENT_PID not found")
	}
	return a, nil
}

// stateFormat renders a exactly like `ssh-agent -s` does, so the state file
// can still be sourced from a shell.
func (a Agent) stateFormat() []byte {
	return fmt.Appendf(nil,
		"SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=%d; export SSH_AGENT_PID;\necho Agent pid %d;\n",
		a.Sock, a.PID, a.PID)
}

// shellExports renders shell code that exports a's environment, for eval.
func (a Agent) shellExports() string {
	return fmt.Sprintf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=%d; export SSH_AGENT_PID;\n",
		shellQuote(a.Sock), a.PID)
}

// environ returns a's environment for exec.Cmd.Env.
func (a Agent) environ() []string {
	return []string{"SSH_AUTH_SOCK=" + a.Sock, "SSH_AGENT_PID=" + strconv.Itoa(a.PID)}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// alive reports whether a's process is running and its socket answers. Both
// are checked: after a reboot the recorded PID may have been reused by an
// unrelated process, and a stale socket file may be left behind.
func (a Agent) alive() bool {
	if a.PID <= 0 || a.Sock == "" {
		return false
	}
	if err := syscall.Kill(a.PID, 0); err != nil {
		return false
	}
	_, err := a.countIdentities()
	return err == nil
}

// SSH agent protocol message numbers (draft-miller-ssh-agent).
const (
	agentFailure            = 5
	agentcRequestIdentities = 11
	agentIdentitiesAnswer   = 12
)

const agentTimeout = 2 * time.Second

// countIdentities asks the agent how many identities it holds.
func (a Agent) countIdentities() (int, error) {
	conn, err := net.DialTimeout("unix", a.Sock, agentTimeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(agentTimeout)); err != nil {
		return 0, err
	}
	// Each message is a uint32 length followed by a type byte and its body.
	if _, err := conn.Write([]byte{0, 0, 0, 1, agentcRequestIdentities}); err != nil {
		return 0, err
	}
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, err
	}
	switch hdr[4] {
	case agentIdentitiesAnswer:
	case agentFailure:
		return 0, errors.New("agent refused to list identities")
	default:
		return 0, fmt.Errorf("unexpected agent reply type %d", hdr[4])
	}
	var n [4]byte
	if _, err := io.ReadFull(conn, n[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint32(n[:])), nil
}

// startAgent launches a new ssh-agent. It daemonizes itself, so this returns
// as soon as it is ready.
func startAgent() (Agent, error) {
	out, err := exec.Command("ssh-agent", "-s").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			err = fmt.Errorf("%w: %s", err, bytes.TrimSpace(ee.Stderr))
		}
		return Agent{}, fmt.Errorf("start ssh-agent: %w", err)
	}
	a, err := parseAgentEnv(out)
	if err != nil {
		return Agent{}, fmt.Errorf("parse ssh-agent output: %w", err)
	}
	return a, nil
}
