package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/observability/healthspool"
	"github.com/HiggsNet/photon/pkg/health"
)

// healthConfig is the application-layer configuration for link health probes
// (Phase 6.6). It maps to the health.* YAML section.
type healthConfig struct {
	Enabled            bool
	Interval           time.Duration
	Timeout            time.Duration
	Burst              int
	LossWindow         int
	Jitter             time.Duration
	MaxConcurrent      int
	FailThreshold      int
	LossThreshold      float64
	DownLossThreshold  float64
	RecoverConsecutive int
	MetricsEnabled     bool

	LocalSpoolPath   string
	LocalSpoolMaxAge time.Duration
}

func (c healthConfig) spoolConfig() healthspool.Config {
	return healthspool.Config{
		Enabled: c.MetricsEnabled,
		Path:    c.LocalSpoolPath,
		MaxAge:  c.LocalSpoolMaxAge,
	}
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
	d := health.DefaultProbeConfig()
	h := health.DefaultHysteresisConfig()
	return healthConfig{
		Enabled:            false,
		Interval:           d.Interval,
		Timeout:            d.Timeout,
		Burst:              d.Burst,
		LossWindow:         d.LossWindow,
		Jitter:             d.Jitter,
		MaxConcurrent:      d.MaxConcurrent,
		FailThreshold:      h.FailThresholdConsecutive,
		LossThreshold:      h.LossThreshold,
		DownLossThreshold:  h.DownLossThreshold,
		RecoverConsecutive: h.RecoverConsecutive,
		MetricsEnabled:     false,
		LocalSpoolMaxAge:   6 * time.Hour,
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
		out.Interval = d
	}
	if y.Timeout != "" {
		d, err := parseConfigDuration(y.Timeout, "health.timeout")
		if err != nil {
			return healthConfig{}, err
		}
		if d <= 0 {
			return healthConfig{}, fmt.Errorf("health.timeout must be positive")
		}
		out.Timeout = d
	}
	if y.Burst != nil {
		if *y.Burst <= 0 {
			return healthConfig{}, fmt.Errorf("health.burst must be positive")
		}
		out.Burst = *y.Burst
	}
	if y.LossWindow != nil {
		if *y.LossWindow <= 0 {
			return healthConfig{}, fmt.Errorf("health.loss_window must be positive")
		}
		out.LossWindow = *y.LossWindow
	}
	if y.Jitter != "" {
		d, err := parseConfigDuration(y.Jitter, "health.jitter")
		if err != nil {
			return healthConfig{}, err
		}
		out.Jitter = d
	}
	if y.MaxConcurrent != nil {
		if *y.MaxConcurrent <= 0 {
			return healthConfig{}, fmt.Errorf("health.max_concurrent_probes must be positive")
		}
		out.MaxConcurrent = *y.MaxConcurrent
	}
	if y.FailThreshold != nil {
		if *y.FailThreshold <= 0 {
			return healthConfig{}, fmt.Errorf("health.fail_threshold_consecutive must be positive")
		}
		out.FailThreshold = *y.FailThreshold
	}
	if y.LossThreshold != "" {
		v, err := parseFloatRatio(y.LossThreshold, "health.loss_threshold")
		if err != nil {
			return healthConfig{}, err
		}
		out.LossThreshold = v
	}
	if y.DownLossThreshold != "" {
		v, err := parseFloatRatio(y.DownLossThreshold, "health.down_loss_threshold")
		if err != nil {
			return healthConfig{}, err
		}
		out.DownLossThreshold = v
	}
	if out.DownLossThreshold < out.LossThreshold {
		return healthConfig{}, fmt.Errorf("health.down_loss_threshold (%g) must be >= health.loss_threshold (%g)", out.DownLossThreshold, out.LossThreshold)
	}
	if y.RecoverConsecutive != nil {
		if *y.RecoverConsecutive <= 0 {
			return healthConfig{}, fmt.Errorf("health.recover_consecutive must be positive")
		}
		out.RecoverConsecutive = *y.RecoverConsecutive
	}
	if y.Metrics != nil {
		// Metrics persistence is opt-in. A metrics block often only carries a
		// destination or retention setting; treating that presence as permission
		// to enable the local JSONL spool can create substantial steady-state I/O.
		metricsEnabled, err := enabledFromPresence("health.metrics.enabled", "health.metrics.disabled", false, y.Metrics.Enabled, y.Metrics.Disabled)
		if err != nil {
			return healthConfig{}, err
		}
		out.MetricsEnabled = metricsEnabled
		if y.Metrics.RemoteWriteURL != nil || y.Metrics.RemoteWriteQueue != nil {
			return healthConfig{}, fmt.Errorf("health.metrics.remote_write_url and remote_write_queue_capacity are not supported; remove these settings")
		}
		if y.Metrics.LocalSpoolPath != "" {
			out.LocalSpoolPath = y.Metrics.LocalSpoolPath
		}
		if y.Metrics.LocalSpoolMaxAge != "" {
			d, err := parseConfigDuration(y.Metrics.LocalSpoolMaxAge, "health.metrics.local_spool_max_age")
			if err != nil {
				return healthConfig{}, err
			}
			out.LocalSpoolMaxAge = d
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

// healthProbeConfig converts healthConfig into the pkg/health.ProbeConfig.
func (c healthConfig) probeConfig() health.ProbeConfig {
	return health.ProbeConfig{
		Interval:      c.Interval,
		Timeout:       c.Timeout,
		Burst:         c.Burst,
		LossWindow:    c.LossWindow,
		Jitter:        c.Jitter,
		MaxConcurrent: c.MaxConcurrent,
	}
}

// healthHysteresisConfig converts healthConfig into the pkg/health.HysteresisConfig.
func (c healthConfig) hysteresisConfig() health.HysteresisConfig {
	return health.HysteresisConfig{
		FailThresholdConsecutive: c.FailThreshold,
		LossThreshold:            c.LossThreshold,
		DownLossThreshold:        c.DownLossThreshold,
		RecoverConsecutive:       c.RecoverConsecutive,
	}
}
