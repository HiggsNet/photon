package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

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
	case "status", "peers", "routes", "diagnostics", "stop":
		return runControl(args[0], args[1:], stdout, stderr)
	case "service":
		return runServiceCommand(args[1:], stdout, stderr)
	case "state":
		return runState(args[1:], stdout, stderr)
	case "gateways":
		return runGateways(args[1:], stdout, stderr)
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

func runConsole(ctx context.Context, args []string, stderr io.Writer) (code int) {
	flags := flag.NewFlagSet("photon-windows run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	console := flags.Bool("console", false, "run in the foreground")
	service := flags.Bool("service", false, "run under Windows SCM")
	name := flags.String("name", photonwindows.DefaultServiceName, "SCM service name")
	path := flags.String("config", "", "path to Photon Windows YAML config")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *console == *service || *path == "" || flags.NArg() != 0 || !validServiceName(*name) {
		fmt.Fprintln(stderr, "Usage: photon-windows run --console --config <path> | run --service --config <path> [--name <name>]")
		return 2
	}
	config, err := photonwindows.LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *service && (!filepath.IsAbs(*path) || !filepath.IsAbs(config.State.Path)) {
		fmt.Fprintln(stderr, "service mode requires absolute config and state.path paths")
		return 1
	}
	var consoleOutput io.Writer = stderr
	serviceName := ""
	if *service {
		consoleOutput = nil
		serviceName = *name
	}
	logger, logCloser, err := photonwindows.NewRuntimeLogger(config, consoleOutput, serviceName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer func() {
		if err := logCloser.Close(); err != nil {
			fmt.Fprintln(stderr, err)
			code = 1
		}
	}()
	var runErr error
	if *service {
		runErr = photonwindows.RunService(*name, config, logger)
	} else {
		runErr = photonwindows.RunConsole(ctx, config, logger)
	}
	if err := runErr; err != nil {
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
	fmt.Fprintln(w, "  status|peers|routes|diagnostics|stop --config <path>  Query or stop the live daemon")
	fmt.Fprintln(w, "  gateways --config <path>         Inspect signed gateway contacts offline (no route authorization)")
	fmt.Fprintln(w, "  state import --config <path> --bundle <file> --key <file>  Initialize a new state database")
	fmt.Fprintln(w, "  run --console --config <path>    Run the Windows leaf daemon in the foreground")
	fmt.Fprintln(w, "  run --service --config <path>    SCM service entrypoint")
	fmt.Fprintln(w, "  service install|start|stop|remove [--name <name>] [--config <path>]")
	fmt.Fprintln(w, "  config validate --config <path>  Validate configuration without starting the service")
	fmt.Fprintln(w, "  version                          Show build information")
	fmt.Fprintln(w, "  help                             Show this help")
	fmt.Fprintln(w, "")
}
