package main

import (
	"fmt"
	"io"
	"os"
)

var (
	buildCommit   = "unknown"
	buildDescribe = "unknown"
	buildDirty    = "unknown"
	buildTime     = "unknown"
)

func main() { os.Exit(run(defaultCommandArgs(os.Args[1:]), os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: photon-windows-gui [gui] [--config <path>] | version")
		return 2
	}
	switch args[0] {
	case "gui":
		return runGUI(args[1:], stderr)
	case "version", "--version", "-version":
		if len(args) != 1 {
			return 2
		}
		fmt.Fprintf(stdout, "photon-windows-gui %s\ncommit: %s\ndirty: %s\nbuilt_at: %s\n", buildDescribe, buildCommit, buildDirty, buildTime)
		return 0
	default:
		return runGUI(args, stderr)
	}
}
