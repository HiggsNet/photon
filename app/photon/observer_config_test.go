package main

import "testing"

func TestParseObserverConfig(t *testing.T) {
	disabled := true
	for _, tc := range []struct {
		name    string
		input   *observerConfigYAML
		want    observerConfig
		wantErr bool
	}{
		{"absent", nil, observerConfig{BindAddr: "127.0.0.1", Port: 8080}, false},
		{"public", &observerConfigYAML{Listen: "0.0.0.0:9090"}, observerConfig{Enabled: true, BindAddr: "0.0.0.0", Port: 9090}, false},
		{"loopback", &observerConfigYAML{Listen: "127.0.0.1:9090"}, observerConfig{Enabled: true, BindAddr: "127.0.0.1", Port: 9090}, false},
		{"disabled", &observerConfigYAML{Disabled: &disabled}, observerConfig{BindAddr: "127.0.0.1", Port: 8080}, false},
		{"invalid_port", &observerConfigYAML{Listen: "127.0.0.1:70000"}, observerConfig{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseObserverConfig(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error: %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("config = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestObserverConfigAddress(t *testing.T) {
	for _, tc := range []struct {
		host     string
		address  string
		loopback bool
	}{
		{"127.0.0.1", "127.0.0.1:8080", true},
		{"::1", "[::1]:8080", true},
		{"10.0.0.1", "10.0.0.1:8080", false},
		{"0.0.0.0", "0.0.0.0:8080", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			cfg := observerConfig{BindAddr: tc.host, Port: 8080}
			if got := cfg.listenAddr(); got != tc.address {
				t.Errorf("listenAddr() = %q, want %q", got, tc.address)
			}
			if got := cfg.isLoopbackBind(); got != tc.loopback {
				t.Errorf("isLoopbackBind() = %v, want %v", got, tc.loopback)
			}
		})
	}
}

func TestObserverConfigFromYAML(t *testing.T) {
	for _, tc := range []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{"listen", "observer:\n  listen: '127.0.0.1:8080'\n", false},
		{"empty_section", "observer:\n", false},
		{"unknown_field", "observer:\n  unknown_field: true\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := defaultAppConfig()
			err := parseConfigYAML(tc.yaml, config)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error: %v", err, tc.wantErr)
			}
			want := observerConfig{Enabled: true, BindAddr: "127.0.0.1", Port: 8080}
			if !tc.wantErr && config.Observer != want {
				t.Errorf("config = %+v, want %+v", config.Observer, want)
			}
		})
	}
}
