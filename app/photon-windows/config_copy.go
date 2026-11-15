package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/HiggsNet/photon/internal/photonwindows/configedit"
)

func runConfigCopy(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("photon-windows config copy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("config", "", "source YAML")
	destination := flags.String("destination", "", "YAML in an empty destination directory")
	elevate := flags.Bool("elevate", false, "request administrator access to copy identity")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*source) || !filepath.IsAbs(*destination) {
		fmt.Fprintln(stderr, "source and destination must be absolute YAML paths")
		return 2
	}
	var err error
	if *elevate {
		err = elevatedConfigCopy(*source, *destination)
	} else {
		err = configedit.Copy(*source, *destination)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, *destination)
	return 0
}
