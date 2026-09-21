package main

import "testing"

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
