package main

import (
	"strings"
	"testing"
	"time"
)

func TestLargeHealthProbeConfig(t *testing.T) {
	enabled := true
	for _, tc := range []struct {
		name        string
		input       *healthLargeProbeYAML
		wantEnabled bool
		wantErr     string
	}{
		{name: "absent"},
		{name: "empty is disabled", input: &healthLargeProbeYAML{}},
		{name: "interval alone is disabled", input: &healthLargeProbeYAML{Interval: "15m"}},
		{name: "explicit enable", input: &healthLargeProbeYAML{Enabled: &enabled, Interval: "15m"}, wantEnabled: true},
		{name: "zero interval", input: &healthLargeProbeYAML{Interval: "0s"}, wantErr: "interval must be positive"},
		{name: "negative interval", input: &healthLargeProbeYAML{Interval: "-1s"}, wantErr: "interval must be positive"},
		{name: "bad size", input: &healthLargeProbeYAML{PacketSize: newInt(1401)}, wantErr: "packet_size"},
		{name: "short size", input: &healthLargeProbeYAML{PacketSize: newInt(48)}, wantErr: "packet_size"},
		{name: "bad window", input: &healthLargeProbeYAML{LossWindow: newInt(0)}, wantErr: "loss_window"},
		{name: "contradictory enable", input: &healthLargeProbeYAML{Enabled: &enabled, Disabled: &enabled}, wantErr: "enabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseHealthConfig(&healthConfigYAML{LargeProbe: tc.input})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Probe.Large.Enabled != tc.wantEnabled || cfg.Probe.Large.PacketSize != 1200 || cfg.Probe.Burst != 3 {
				t.Fatalf("config = %+v", cfg.Probe)
			}
			if tc.input != nil && tc.input.Interval == "15m" && cfg.Probe.Large.Interval != 15*time.Minute {
				t.Fatal("large interval was not applied")
			}
		})
	}
}

func newInt(v int) *int { return &v }

func TestLargeHealthProbeConfigFromYAML(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML(`health:
  interval: 6s
  burst: 1
  large_probe:
    enabled: true
    interval: 2m
    packet_size: 1300
    loss_window: 120
`, config); err != nil {
		t.Fatal(err)
	}
	if config.Health.Probe.Large.Interval != 2*time.Minute || config.Health.Probe.Large.PacketSize != 1300 || config.Health.Probe.Large.LossWindow != 120 || !config.Health.Probe.Large.Enabled {
		t.Fatalf("large probe not parsed: %+v", config.Health.Probe)
	}
}

func TestParseHealthConfigDefault(t *testing.T) {
	cfg, err := parseHealthConfig(nil)
	if err != nil {
		t.Fatalf("parseHealthConfig(nil): %v", err)
	}
	if cfg.Enabled {
		t.Fatal("default health should be disabled")
	}
}

func TestParseHealthConfigEnabledByPresence(t *testing.T) {
	cfg, err := parseHealthConfig(&healthConfigYAML{})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("health should be enabled when the section is present")
	}
}

func TestHealthConfigFromEmptyYAMLSection(t *testing.T) {
	yaml := `health:
`
	config := defaultAppConfig()
	if err := parseConfigYAML(yaml, config); err != nil {
		t.Fatalf("parseConfigYAML error: %v", err)
	}
	if !config.Health.Enabled {
		t.Fatal("empty health section should enable health")
	}
}

func TestParseHealthConfigDisabled(t *testing.T) {
	disabled := true
	cfg, err := parseHealthConfig(&healthConfigYAML{Disabled: &disabled})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("health should be disabled")
	}
}

func TestParseHealthConfigMetricsDisabledByDefault(t *testing.T) {
	cfg, err := parseHealthConfig(&healthConfigYAML{Metrics: &healthMetricsYAML{}})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if cfg.Spool.Enabled {
		t.Fatal("health metrics should remain disabled without explicit enablement")
	}
}

func TestParseHealthConfigMetricsEnabledExplicitly(t *testing.T) {
	enabled := true
	cfg, err := parseHealthConfig(&healthConfigYAML{Metrics: &healthMetricsYAML{Enabled: &enabled}})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if !cfg.Spool.Enabled {
		t.Fatal("health metrics should be enabled explicitly")
	}
}

func TestParseHealthConfigMetricsDisabled(t *testing.T) {
	disabled := true
	cfg, err := parseHealthConfig(&healthConfigYAML{Metrics: &healthMetricsYAML{Disabled: &disabled}})
	if err != nil {
		t.Fatalf("parseHealthConfig: %v", err)
	}
	if cfg.Spool.Enabled {
		t.Fatal("health metrics should be disabled")
	}
}
