package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"slices"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

// Control commands read only public configuration to locate the running owner.
// They never open Bolt or load/create a local identity.
func runControl(method string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("photon-windows "+method, flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "path to Photon Windows YAML config")
	var destination *string
	if method == "routes" {
		destination = flags.String("destination", "", "filter the Babel route sample by destination IP")
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *path == "" || flags.NArg() != 0 {
		fmt.Fprintf(stderr, "Usage: photon-windows %s --config <path>\n", method)
		return 2
	}
	var target netip.Addr
	if destination != nil && *destination != "" {
		var err error
		target, err = netip.ParseAddr(*destination)
		if err != nil || target.Zone() != "" {
			fmt.Fprintln(stderr, "--destination requires an IPv4 or IPv6 address without a zone")
			return 2
		}
		target = target.Unmap()
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
	if target.IsValid() && response.Error == nil {
		var sample struct {
			Routes    []photonwindows.RouteObservation `json:"routes"`
			Truncated bool                             `json:"truncated"`
		}
		if err := json.Unmarshal(response.Result, &sample); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		sample.Routes = slices.DeleteFunc(sample.Routes, func(route photonwindows.RouteObservation) bool {
			return !route.Prefix.Contains(target)
		})
		response.Result, err = json.Marshal(sample)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
