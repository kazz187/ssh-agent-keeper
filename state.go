package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// The state file records the agent every shell should use, in the format of
// `ssh-agent -s` output. Everything here holds an flock on it while reading or
// writing, so shells starting at the same time agree on a single agent. It is
// always rewritten in place, never replaced by a rename, so the lock and the
// file watch stay on the same file.

// withState opens the state file, creating it if needed, and calls fn while
// holding a lock of kind how (syscall.LOCK_SH or syscall.LOCK_EX) on it.
func withState(path string, how int, fn func(f *os.File) error) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	// Closing f releases the lock. Go opens files with O_CLOEXEC, so an
	// ssh-agent started while the lock is held does not inherit it.
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		return fmt.Errorf("lock %s: %w", path, err)
	}
	return fn(f)
}

func readAgent(f *os.File) (Agent, error) {
	b, err := io.ReadAll(io.NewSectionReader(f, 0, 1<<16))
	if err != nil {
		return Agent{}, err
	}
	return parseAgentEnv(b)
}

func writeAgent(f *os.File, a Agent) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err := f.WriteAt(a.stateFormat(), 0)
	return err
}

// ensureAgent returns the agent recorded in the state file, starting and
// recording a new one when there is none or it is no longer running. The
// file's directory is created if missing.
func ensureAgent(path string) (Agent, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Agent{}, err
	}
	var agent Agent
	err := withState(path, syscall.LOCK_EX, func(f *os.File) error {
		if a, err := readAgent(f); err == nil && a.alive() {
			agent = a
			return nil
		}
		a, err := startAgent()
		if err != nil {
			return err
		}
		agent = a
		return writeAgent(f, a)
	})
	return agent, err
}

// loadAgent returns the agent recorded in the state file.
func loadAgent(path string) (Agent, error) {
	var agent Agent
	err := withState(path, syscall.LOCK_SH, func(f *os.File) (err error) {
		agent, err = readAgent(f)
		return err
	})
	return agent, err
}

// announce tells the shells watching the state file that identities have been
// added to agent, by rewriting the file with the same content: the write
// itself is the signal. If the file has meanwhile moved on to another agent,
// it is left alone.
func announce(path string, agent Agent) error {
	return withState(path, syscall.LOCK_EX, func(f *os.File) error {
		if cur, err := readAgent(f); err != nil || cur != agent {
			return nil
		}
		return writeAgent(f, agent)
	})
}
