package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func validServiceName(name string) bool {
	return name != "" && len(name) <= 128 && !strings.ContainsAny(name, "/\\\x00\r\n")
}

func runServiceCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: photon-windows service install|start|stop|remove [--name <name>] [--config <path>]")
		return 2
	}
	action := args[0]
	switch action {
	case "install", "start", "stop", "remove":
	default:
		fmt.Fprintf(stderr, "unknown service action %q\n", action)
		return 2
	}
	flags := flag.NewFlagSet("photon-windows service "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", photonwindows.DefaultServiceName, "SCM service name")
	config := flags.String("config", "", "config path (required for install)")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 || !validServiceName(*name) || (action == "install" && *config == "") {
		fmt.Fprintln(stderr, "install requires --config; service name must be valid and extra arguments are not accepted")
		return 2
	}
	path := ""
	if *config != "" {
		var err error
		path, err = filepath.Abs(*config)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if action == "install" {
		config, err := photonwindows.LoadConfig(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if !filepath.IsAbs(config.State.Path) {
			fmt.Fprintln(stderr, "service installation requires an absolute state.path in config")
			return 1
		}
	}
	if err := manageService(action, *name, path); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "service %s: %s completed\n", *name, action)
	return 0
}
