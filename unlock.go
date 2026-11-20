package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/fswatcher/fswatcher"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// unlock makes sure the agent holds identities, running ssh-add on the
// terminal when it holds none, and returns the agent the shell should use.
//
// When many shells start at once (a terminal restoring its windows), every one
// of them prompts. The first prompt answered wins: its shell announces that
// through the state file, and the other shells, watching the file, find the
// agent holding identities, abandon their own prompts and carry on.
func unlock(path string, agent Agent, keys []string) (Agent, error) {
	// Without a watch, still prompt; only the other windows go unnoticed.
	var events <-chan fswatcher.Event
	var errs <-chan error
	w, err := watch(path)
	if err != nil {
		info(fmt.Sprintf("cannot watch %s, so a passphrase entered in another window will go unnoticed: %v", path, err))
	} else {
		defer w.Close()
		events, errs = w.Events, w.Errors
	}

	// Checked only once the watch is in place, so that an announcement made
	// in between cannot be missed.
	if n, err := agent.countIdentities(); err != nil || n > 0 {
		return agent, err
	}

	stdin := int(os.Stdin.Fd())
	tty, err := term.GetState(stdin)
	if err != nil {
		return agent, err
	}
	fg, err := unix.IoctlGetInt(stdin, unix.TIOCGPGRP)
	if err != nil {
		return agent, err
	}

	info("enter the passphrase here or in any other window")
	cmd := exec.Command("ssh-add", keys...)
	cmd.Env = append(os.Environ(), agent.environ()...)
	// Stdout is for the shell to eval, so ssh-add's messages go to stderr.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	// Run ssh-add as the terminal's foreground job, like a shell does, so
	// that Ctrl-C only skips its prompt instead of also aborting the shell's
	// startup file.
	cmd.SysProcAttr = &syscall.SysProcAttr{Foreground: true, Ctty: stdin}
	if err := cmd.Start(); err != nil {
		return agent, err
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	// Once ssh-add is gone, take the terminal back for the shell.
	reclaimTTY := func() {
		_ = setForeground(stdin, fg)
		_ = term.Restore(stdin, tty)
	}

	for {
		select {
		case <-exited:
			reclaimTTY()
			if n, err := agent.countIdentities(); err == nil && n > 0 {
				if err := announce(path, agent); err != nil {
					return agent, fmt.Errorf("announce to other windows: %w", err)
				}
			}
			return agent, nil

		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if ev.Op.Has(fswatcher.Remove | fswatcher.Rename) {
				// The watch went away with the file; follow its replacement.
				_ = w.Add(path, fswatcher.All)
			}
			cur, err := loadAgent(path)
			if err != nil {
				continue
			}
			if n, err := cur.countIdentities(); err != nil || n == 0 {
				continue
			}
			stopSSHAdd(cmd, exited)
			reclaimTTY()
			info("identities were added in another window")
			return cur, nil

		case _, ok := <-errs:
			// Dropped events are harmless: the next one re-checks the agent.
			if !ok {
				errs = nil
			}
		}
	}
}

func watch(path string) (*fswatcher.Watcher, error) {
	w, err := fswatcher.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := w.Add(path, fswatcher.All); err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

// setForeground makes pgrp the terminal's foreground process group. This
// process is in the background at that point, and would be stopped by
// SIGTTOU unless it ignores it.
func setForeground(fd, pgrp int) error {
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	return unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgrp)
}

// stopSSHAdd abandons an ssh-add waiting for a passphrase. On SIGTERM it
// restores the terminal settings itself before exiting.
func stopSSHAdd(cmd *exec.Cmd, exited <-chan struct{}) {
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
	}
}
