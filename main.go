// Command ssh-agent-keeper shares one ssh-agent among all shells and asks for
// the key passphrase only once, even when many shells start at the same time.
//
// It prints shell code that sets SSH_AUTH_SOCK and SSH_AGENT_PID, so call it
// from the shell's startup file:
//
//	eval "$(ssh-agent-keeper)"
//
// The agent is recorded in a pid file (~/.config/ssh-agent-keeper/ssh-agent-pid
// by default) in the format of `ssh-agent -s` output. If the agent it records
// is not running, a new one is started. If the agent holds no identities and
// stdin is a terminal, ssh-add is run with the given keys; all shells waiting
// on a passphrase continue as soon as it has been entered in any one of them.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"golang.org/x/term"
)

const defaultPidFile = ".config/ssh-agent-keeper/ssh-agent-pid" // under $HOME

type options struct {
	pidFile string
	keys    []string
}

// parseArgs parses the command line. Paths starting with ~/ are expanded
// against home, as shells leave the ~ in --pid-file=~/... alone.
func parseArgs(args []string, home string) (options, error) {
	app := kingpin.New("ssh-agent-keeper",
		"Share one ssh-agent among all shells, asking for the key passphrase only once.\n\n"+
			"Prints shell code that sets SSH_AUTH_SOCK and SSH_AGENT_PID, to use as:\n\n"+
			`  eval "$(ssh-agent-keeper)"`)
	// Stdout is for the shell to eval.
	app.UsageWriter(os.Stderr)
	app.HelpFlag.Short('h')

	var opts options
	app.Flag("pid-file", "File recording the agent, in `ssh-agent -s` output format.").
		Short('f').PlaceHolder("~/" + defaultPidFile).
		Default(filepath.Join(home, defaultPidFile)).StringVar(&opts.pidFile)
	app.Flag("key", "Key file for ssh-add to add; repeat for more (default: ssh-add's default keys).").
		Short('k').PlaceHolder("FILE").StringsVar(&opts.keys)

	if _, err := app.Parse(args); err != nil {
		return options{}, err
	}
	opts.pidFile = expandHome(opts.pidFile, home)
	for i, k := range opts.keys {
		opts.keys[i] = expandHome(k, home)
	}
	return opts, nil
}

func expandHome(path, home string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return path
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("ssh-agent-keeper: ")

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	opts, err := parseArgs(os.Args[1:], home)
	if err != nil {
		log.Fatalf("%v, try --help", err)
	}

	agent, err := ensureAgent(opts.pidFile)
	if err != nil {
		log.Fatal(err)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if agent, err = unlock(opts.pidFile, agent, opts.keys); err != nil {
			// The agent is still usable without identities.
			log.Print(err)
		}
	}
	fmt.Print(agent.shellExports())
}

func info(msg string) {
	fmt.Fprintln(os.Stderr, "ssh-agent-keeper: "+msg)
}
