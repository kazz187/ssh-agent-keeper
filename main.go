// Command ssh-agent-keeper shares one ssh-agent among all shells and asks for
// the key passphrase only once, even when many shells start at the same time.
//
// It prints shell code that sets SSH_AUTH_SOCK and SSH_AGENT_PID, so call it
// from the shell's startup file:
//
//	eval "$(ssh-agent-keeper)"
//
// The agent is recorded in a state file (~/.ssh-agent by default) in the
// format of `ssh-agent -s` output. If the recorded agent is not running, a new
// one is started. If the agent holds no identities and stdin is a terminal,
// ssh-add is run; all shells waiting on a passphrase continue as soon as it
// has been entered in any one of them.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/term"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("ssh-agent-keeper: ")

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	file := flag.String("f", filepath.Join(home, ".ssh-agent"),
		"state `file` recording the agent, in `ssh-agent -s` output format")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"usage: eval \"$(ssh-agent-keeper [-f file] [-- ssh-add args...])\"\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	agent, err := ensureAgent(*file)
	if err != nil {
		log.Fatal(err)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if agent, err = unlock(*file, agent, flag.Args()); err != nil {
			// The agent is still usable without identities.
			log.Print(err)
		}
	}
	fmt.Print(agent.shellExports())
}

func info(msg string) {
	fmt.Fprintln(os.Stderr, "ssh-agent-keeper: "+msg)
}
