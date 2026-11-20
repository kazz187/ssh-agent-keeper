// Command ssh-agent-keeper shares one ssh-agent among all shells and asks for
// the key passphrase only once, even when many shells start at the same time.
//
// It prints shell code that sets SSH_AUTH_SOCK and SSH_AGENT_PID, so call it
// from the shell's startup file, giving it the pid file to record the agent in:
//
//	eval "$(ssh-agent-keeper ~/.ssh-agent)"
//
// The pid file has the format of `ssh-agent -s` output. If the agent it
// records is not running, a new one is started. If the agent holds no
// identities and stdin is a terminal, ssh-add is run with the remaining
// arguments; all shells waiting on a passphrase continue as soon as it has
// been entered in any one of them.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/term"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("ssh-agent-keeper: ")

	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(),
			`usage: eval "$(ssh-agent-keeper <pid file> [ssh-add args...])"`)
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	file, sshAddArgs := flag.Arg(0), flag.Args()[1:]

	agent, err := ensureAgent(file)
	if err != nil {
		log.Fatal(err)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if agent, err = unlock(file, agent, sshAddArgs); err != nil {
			// The agent is still usable without identities.
			log.Print(err)
		}
	}
	fmt.Print(agent.shellExports())
}

func info(msg string) {
	fmt.Fprintln(os.Stderr, "ssh-agent-keeper: "+msg)
}
