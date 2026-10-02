package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

var (
	buildCommit   = "unknown"
	buildDescribe = "unknown"
	buildDirty    = "unknown"
	buildTime     = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return 2
	}
	switch args[0] {
	case "state":
		return runState(args[1:], stdout, stderr)
	case "run":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return runConsole(ctx, args[1:], stderr)
	case "version", "--version", "-version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "photon-windows version accepts no arguments")
			return 2
		}
		fmt.Fprintf(stdout, "photon-windows %s\ncommit: %s\ndirty: %s\nbuilt_at: %s\n", buildDescribe, buildCommit, buildDirty, buildTime)
		return 0
	case "help", "--help", "-h":
		writeUsage(stdout)
		return 0
	case "config":
		return runConfig(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown photon-windows command %q\n", args[0])
		writeUsage(stderr)
		return 2
	}
}

func runConsole(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("photon-windows run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	console := flags.Bool("console", false, "run in the foreground")
	path := flags.String("config", "", "path to Photon Windows YAML config")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*console || *path == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Usage: photon-windows run --console --config <path>")
		return 2
	}
	config, err := photonwindows.LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(config.Log.Level))
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	if err := photonwindows.RunConsole(ctx, config, logger); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(stderr, "Usage: photon-windows config validate --config <path>")
		return 2
	}
	flags := flag.NewFlagSet("photon-windows config validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "path to Photon Windows YAML config")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *path == "" {
		fmt.Fprintln(stderr, "Usage: photon-windows config validate --config <path>")
		return 2
	}
	config, err := photonwindows.LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "valid Photon Windows config (schema %d): %s\n", config.SchemaVersion, *path)
	return 0
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: photon-windows <command>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  state import --config <path> --bundle <file> --key <file>  Initialize a new state database")
	fmt.Fprintln(w, "  run --console --config <path>    Restore state and run Gossip (no tunnel yet)")
	fmt.Fprintln(w, "  config validate --config <path>  Validate configuration without starting the service")
	fmt.Fprintln(w, "  version                          Show build information")
	fmt.Fprintln(w, "  help                             Show this help")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The Wintun/service runtime is being implemented and is not advertised as ready yet.")
}
