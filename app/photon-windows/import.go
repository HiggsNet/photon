package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/share"
)

func runState(args []string, stdout, stderr io.Writer) int {
	const usage = "Usage: photon-windows state import --config <path> --bundle <file> --key <file>"
	if len(args) == 0 || args[0] != "import" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	flags := flag.NewFlagSet("photon-windows state import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "Windows configuration")
	bundlePath := flags.String("bundle", "", "Photon join bundle file (JSON or Base64 JSON)")
	keyPath := flags.String("key", "", "Photon Ed25519 private key JSON file")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *configPath == "" || *bundlePath == "" || *keyPath == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err := importStateFiles(*configPath, *bundlePath, *keyPath); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "Photon state imported; run --console --config to start Gossip (no tunnel yet)")
	return 0
}

func importStateFiles(configPath, bundlePath, keyPath string) error {
	config, err := photonwindows.LoadConfig(configPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return err
	}
	var bundle share.JoinBundle
	if json.Valid(data) {
		err = json.Unmarshal(data, &bundle)
	} else {
		err = share.DecodeBase64JSON(string(data), &bundle)
	}
	if err != nil {
		return fmt.Errorf("decode join bundle: %w", err)
	}
	data, err = os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	var key share.PrivateKeyFile
	if err := json.Unmarshal(data, &key); err != nil {
		return fmt.Errorf("decode key file: %w", err)
	}
	return photonwindows.ImportState(context.Background(), config, &bundle, &key)
}
