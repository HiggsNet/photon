package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func parseDesktopOptions(args []string, stderr io.Writer) (desktopOptions, error) {
	flags := flag.NewFlagSet("photon-windows gui", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "configuration file (default: config.yaml beside the executable)")
	name := flags.String("name", photonwindows.DefaultServiceName, "SCM service name")
	if err := flags.Parse(args); err != nil {
		return desktopOptions{}, err
	}
	if flags.NArg() != 0 || !validServiceName(*name) {
		return desktopOptions{}, errors.New("Usage: photon-windows gui [--config <path>] [--name <name>]")
	}
	if *path == "" {
		executable, err := os.Executable()
		if err != nil {
			return desktopOptions{}, err
		}
		*path = filepath.Join(filepath.Dir(executable), "config.yaml")
	}
	absolute, err := filepath.Abs(*path)
	if err != nil {
		return desktopOptions{}, err
	}
	return desktopOptions{ConfigPath: absolute, ServiceName: *name}, nil
}

func runGUI(args []string, stderr io.Writer) int {
	options, err := parseDesktopOptions(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := runDesktop(options); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
