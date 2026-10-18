package main

import (
	"os"
	"strings"
	"testing"
)

// The device example must parse through the real Linux composition root both
// before provisioning and with its documented data-plane blocks enabled.
func TestOpenWrtConfigExample(t *testing.T) {
	data, err := os.ReadFile("../../contrib/openwrt/files/config.yaml.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, active := range []bool{false, true} {
		name := "initial"
		input := string(data)
		if active {
			name = "data-plane"
			start := strings.Index(input, "# netns:")
			end := strings.Index(input, "#\n# Host ingress")
			if start < 0 || end <= start {
				t.Fatal("missing data-plane example block")
			}
			input = input[:start] + strings.ReplaceAll(input[start:end], "# ", "") + input[end:]
		}
		t.Run(name, func(t *testing.T) {
			config := defaultAppConfig()
			if err := parseConfigYAML(input, config); err != nil {
				t.Fatal(err)
			}
			normalizeAppConfig(config)
			if config.StatePath != "/etc/photon/photon.db" || config.Log.Mode != "stderr" {
				t.Fatalf("unexpected persistence/log settings: %s, %+v", config.StatePath, config.Log)
			}
			if !active {
				if len(config.IPsec.LinkGroups) != 0 || len(config.Routing.Instances) != 0 || len(config.Firewall.Instances) != 0 {
					t.Fatal("unprovisioned example enables a data-plane layer")
				}
				return
			}
			if len(config.IPsec.LinkGroups) != 1 || len(config.Routing.Instances) != 1 || len(config.Firewall.Instances) != 1 {
				t.Fatal("data-plane example did not enable all three layers")
			}
			bird := config.Routing.Instances[0]
			if bird.ShutdownPolicy != "stop" || !strings.HasPrefix(bird.Bird.ConfigPath, "/run/photon/") || !strings.HasPrefix(bird.Bird.ControlSocketPath, "/run/photon/") || !strings.HasPrefix(bird.Bird.PIDFilePath, "/run/photon/") {
				t.Fatalf("BIRD must use volatile paths and stop with Photon: %+v", bird)
			}
		})
	}
}
