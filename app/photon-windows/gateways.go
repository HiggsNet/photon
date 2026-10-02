package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func runGateways(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("photon-windows gateways", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "Windows configuration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *path == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Usage: photon-windows gateways --config <path>")
		return 2
	}
	config, err := photonwindows.LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	state, err := photonwindows.OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, time.Second)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	view, err := state.ReadView(context.Background())
	closeErr := state.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	now := time.Now()
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(map[string]any{"revision": view.Revision, "evaluated_at": now, "tunnel_ready": false, "route_authorized": false, "candidates": photonwindows.GatewayCandidates(config, view, now)})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
