package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

// Control commands read only public configuration to locate the running owner.
// They never open Bolt or load/create a local identity.
func runControl(method string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("photon-windows "+method, flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "path to Photon Windows YAML config")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *path == "" || flags.NArg() != 0 {
		fmt.Fprintf(stderr, "Usage: photon-windows %s --config <path>\n", method)
		return 2
	}
	config, err := photonwindows.LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	response, err := photonwindows.CallControl(context.Background(), config.State.Path, method)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
