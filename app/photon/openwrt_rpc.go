//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/photonopenwrt"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

func platformAdvancedCommands() []*cli.Command {
	return []*cli.Command{cmdOpenWrtRPC()}
}

func cmdOpenWrtRPC() *cli.Command {
	return &cli.Command{
		Name: "openwrt-rpc", Usage: "Serve the local OpenWrt rpcd management adapter",
		UsageText: "photon advanced openwrt-rpc list|call <method>",
		Action: func(ctx context.Context, command *cli.Command) error {
			ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
			defer cancel()
			adapter := photonopenwrt.New(photonopenwrt.Options{
				Validate: func(content string) error {
					_, err := parseOpenWrtConfig(content)
					return err
				},
				Views: openWrtControlViews,
			})
			return adapter.Serve(ctx, command.Args().Slice(), os.Stdin, os.Stdout)
		},
	}
}

// Use the real Linux configuration parser. The management editor additionally
// requires a single mapping document, so a valid first document cannot hide
// accidentally appended configuration that the daemon would ignore.
func parseOpenWrtConfig(content string) (*appConfig, error) {
	if len(content) > photonopenwrt.MaxConfigBytes {
		return nil, errors.New("configuration exceeds 128 KiB")
	}
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("configuration must be a YAML mapping")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("configuration must contain exactly one YAML document")
	}
	config := defaultAppConfig()
	if err := parseConfigYAML(content, config); err != nil {
		return nil, err
	}
	normalizeAppConfig(config)
	return config, nil
}

// Query canonical views only over the daemon's local control socket. An offline
// UI request never opens or initializes the persistent database.
func openWrtControlViews(ctx context.Context, configPath string) (photonopenwrt.Views, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return photonopenwrt.Views{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, photonopenwrt.MaxConfigBytes+1))
	if err != nil {
		return photonopenwrt.Views{}, err
	}
	config, err := parseOpenWrtConfig(string(data))
	if err != nil {
		return photonopenwrt.Views{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var views photonopenwrt.Views
	for _, resource := range []struct {
		method string
		target *json.RawMessage
	}{
		{"daemon_status_view", &views.Daemon}, {"status_view", &views.Summary},
		{"peers_view", &views.Peers}, {"links_view", &views.Links},
	} {
		value, online, err := readCanonicalViewViaControlContext[json.RawMessage](ctx, config, controlRequest{Method: resource.method}, false)
		if err != nil {
			return photonopenwrt.Views{}, err
		}
		if !online {
			return photonopenwrt.Views{}, errors.New("Photon control interface is unavailable; no live network status")
		}
		*resource.target = value
	}
	return views, nil
}
