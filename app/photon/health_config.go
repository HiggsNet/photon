package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/observability/healthspool"
	"github.com/HiggsNet/photon/pkg/health"
)

// healthConfig composes module configurations for the health.* YAML section.
type healthConfig struct {
	Enabled    bool
	Probe      health.ProbeConfig
	Hysteresis health.HysteresisConfig
	Spool      healthspool.Config
}

// healthConfigYAML is the YAML representation of healthConfig.
type healthConfigYAML struct {
	Enabled            *bool              `yaml:"enabled"`
	Disabled           *bool              `yaml:"disabled"`
	Interval           string             `yaml:"interval"`
	Timeout            string             `yaml:"timeout"`
	Burst              *int               `yaml:"burst"`
	LossWindow         *int               `yaml:"loss_window"`
	Jitter             string             `yaml:"jitter"`
	MaxConcurrent      *int               `yaml:"max_concurrent_probes"`
	FailThreshold      *int               `yaml:"fail_threshold_consecutive"`
	LossThreshold      string             `yaml:"loss_threshold"`
	DownLossThreshold  string             `yaml:"down_loss_threshold"`
	RecoverConsecutive *int               `yaml:"recover_consecutive"`
	Metrics            *healthMetricsYAML `yaml:"metrics"`
}

type healthMetricsYAML struct {
	Enabled          *bool   `yaml:"enabled"`
	Disabled         *bool   `yaml:"disabled"`
	RemoteWriteURL   *string `yaml:"remote_write_url"`
	RemoteWriteQueue *int    `yaml:"remote_write_queue_capacity"`
	LocalSpoolPath   string  `yaml:"local_spool_path"`
	LocalSpoolMaxAge string  `yaml:"local_spool_max_age"`
}

func defaultHealthConfig() healthConfig {
	return healthConfig{
		Probe:      health.DefaultProbeConfig(),
		Hysteresis: health.DefaultHysteresisConfig(),
		Spool:      healthspool.Config{MaxAge: 6 * time.Hour},
	}
}

func parseHealthConfig(y *healthConfigYAML) (healthConfig, error) {
	out := defaultHealthConfig()
	if y == nil {
		return out, nil
	}
	enabled, err := enabledFromPresence("health.enabled", "health.disabled", true, y.Enabled, y.Disabled)
	if err != nil {
		return healthConfig{}, err
	}
	out.Enabled = enabled
	if y.Interval != "" {
		d, err := parseConfigDuration(y.Interval, "health.interval")
		if err != nil {
			return healthConfig{}, err
		}
		if d <= 0 {
			return healthConfig{}, fmt.Errorf("health.interval must be positive")
		}
		out.Probe.Interval = d
	}
	if y.Timeout != "" {
		d, err := parseConfigDuration(y.Timeout, "health.timeout")
		if err != nil {
			return healthConfig{}, err
		}
		if d <= 0 {
			return healthConfig{}, fmt.Errorf("health.timeout must be positive")
		}
		out.Probe.Timeout = d
	}
	if y.Burst != nil {
		if *y.Burst <= 0 {
			return healthConfig{}, fmt.Errorf("health.burst must be positive")
		}
		out.Probe.Burst = *y.Burst
	}
	if y.LossWindow != nil {
		if *y.LossWindow <= 0 {
			return healthConfig{}, fmt.Errorf("health.loss_window must be positive")
		}
		out.Probe.LossWindow = *y.LossWindow
	}
	if y.Jitter != "" {
		d, err := parseConfigDuration(y.Jitter, "health.jitter")
		if err != nil {
			return healthConfig{}, err
		}
		out.Probe.Jitter = d
	}
	if y.MaxConcurrent != nil {
		if *y.MaxConcurrent <= 0 {
			return healthConfig{}, fmt.Errorf("health.max_concurrent_probes must be positive")
		}
		out.Probe.MaxConcurrent = *y.MaxConcurrent
	}
	if y.FailThreshold != nil {
		if *y.FailThreshold <= 0 {
			return healthConfig{}, fmt.Errorf("health.fail_threshold_consecutive must be positive")
		}
		out.Hysteresis.FailThresholdConsecutive = *y.FailThreshold
	}
	if y.LossThreshold != "" {
		v, err := parseFloatRatio(y.LossThreshold, "health.loss_threshold")
		if err != nil {
			return healthConfig{}, err
		}
		out.Hysteresis.LossThreshold = v
	}
	if y.DownLossThreshold != "" {
		v, err := parseFloatRatio(y.DownLossThreshold, "health.down_loss_threshold")
		if err != nil {
			return healthConfig{}, err
		}
		out.Hysteresis.DownLossThreshold = v
	}
	if out.Hysteresis.DownLossThreshold < out.Hysteresis.LossThreshold {
		return healthConfig{}, fmt.Errorf("health.down_loss_threshold (%g) must be >= health.loss_threshold (%g)", out.Hysteresis.DownLossThreshold, out.Hysteresis.LossThreshold)
	}
	if y.RecoverConsecutive != nil {
		if *y.RecoverConsecutive <= 0 {
			return healthConfig{}, fmt.Errorf("health.recover_consecutive must be positive")
		}
		out.Hysteresis.RecoverConsecutive = *y.RecoverConsecutive
	}
	if y.Metrics != nil {
		// Metrics persistence is opt-in. A metrics block often only carries a
		// destination or retention setting; treating that presence as permission
		// to enable the local JSONL spool can create substantial steady-state I/O.
		metricsEnabled, err := enabledFromPresence("health.metrics.enabled", "health.metrics.disabled", false, y.Metrics.Enabled, y.Metrics.Disabled)
		if err != nil {
			return healthConfig{}, err
		}
		out.Spool.Enabled = metricsEnabled
		if y.Metrics.RemoteWriteURL != nil || y.Metrics.RemoteWriteQueue != nil {
			return healthConfig{}, fmt.Errorf("health.metrics.remote_write_url and remote_write_queue_capacity are not supported; remove these settings")
		}
		if y.Metrics.LocalSpoolPath != "" {
			out.Spool.Path = y.Metrics.LocalSpoolPath
		}
		if y.Metrics.LocalSpoolMaxAge != "" {
			d, err := parseConfigDuration(y.Metrics.LocalSpoolMaxAge, "health.metrics.local_spool_max_age")
			if err != nil {
				return healthConfig{}, err
			}
			out.Spool.MaxAge = d
		}
	}
	return out, nil
}

func parseFloatRatio(s string, name string) (float64, error) {
	s = strings.TrimSpace(s)
	var v float64
	_, err := fmt.Sscanf(s, "%f", &v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %q", name, s)
	}
	if v < 0 || v > 1 {
		return 0, fmt.Errorf("%s must be between 0.0 and 1.0, got %g", name, v)
	}
	return v, nil
}
