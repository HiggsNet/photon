package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestResolveAndRenderManifest(t *testing.T) {
	output := t.TempDir()
	configured := manifest{
		Version: 1, OutputDir: output,
		Images: imageConfig{Gost: defaultGostImage},
		Networks: map[string]networkConfig{
			"main": {IPv4: "local;172.30.0.0/24;172.30.0.128/28;172.30.0.1", IPv6: "auto;::/112;::100/120;::1", TrustedHostInterfaces: []string{"phx1", "phx0"}},
			"cn":   {IPv6: "assignment:fd42:2::/64;::/112;::100/120;::1"},
		},
		SOCKS5: socks5Config{Publish: publishConfig{"main": "cn-east", "cn": "cn"}, Networks: map[string]string{"main": "::20", "cn": "::30"}},
	}
	_, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}, {Prefix: "fd42:2::/64"}})
	if err == nil || !strings.Contains(err.Error(), "auto requires exactly one") {
		t.Fatalf("ambiguous auto error = %v", err)
	}
	configured.Networks["main"] = networkConfig{
		IPv4: configured.Networks["main"].IPv4, IPv6: "assignment:fd42:1::/64;::/112;::100/120;::1",
		TrustedHostInterfaces: configured.Networks["main"].TrustedHostInterfaces,
	}
	resolved, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}, {Prefix: "fd42:2::/64"}})
	if err != nil {
		t.Fatalf("resolveManifest: %v", err)
	}
	service := resolved.SOCKS5
	if len(service.Endpoints) != 2 || service.Endpoints[1].Address != "fd42:1::20" || service.Networks["main"].H2 != "fd42:1::21" {
		t.Fatalf("resolved service = %#v", service)
	}
	if service.Resolver.Mode != "ipv4_first" || strings.Join(service.Resolver.Servers, ",") != "8.8.8.8,1.1.1.1" {
		t.Fatalf("resolved resolver = %#v", service.Resolver)
	}
	if service.HTTPAuth.Username != "photon" || service.HTTPAuth.Password != "2a0d" {
		t.Fatalf("resolved HTTP auth = %#v", service.HTTPAuth)
	}
	resolved.ManagedZone = "node-a.catofes."
	legacyConfig := filepath.Join(output, "socks5", "config", "smartdns.conf")
	if err := os.MkdirAll(filepath.Dir(legacyConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyConfig, []byte("obsolete"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := renderArtifacts(resolved); err != nil {
		t.Fatalf("renderArtifacts: %v", err)
	}
	if _, err := os.Stat(legacyConfig); !os.IsNotExist(err) {
		t.Fatalf("legacy SmartDNS config was not removed: %v", err)
	}
	lock, err := loadRenderedSOCKS5(output)
	if err != nil {
		t.Fatalf("loadRenderedSOCKS5: %v", err)
	}
	if lock.ManagedZone != resolved.ManagedZone || len(lock.Endpoints) != 2 {
		t.Fatalf("rendered lock = %+v", lock)
	}
	networkCompose := readTestFile(t, filepath.Join(output, "networks", "docker-compose.yml"))
	for _, want := range []string{"services:", "owner:", "scale: 0", "name: photon-main", "fd42:1::/112", "driver_opts:", "com.docker.network.bridge.trusted_host_interfaces: phx0:phx1", "com.docker.network.bridge.gateway_mode_ipv6: nat-unprotected"} {
		if !strings.Contains(networkCompose, want) {
			t.Fatalf("network compose missing %q:\n%s", want, networkCompose)
		}
	}
	serviceCompose := readTestFile(t, filepath.Join(output, "socks5", "docker-compose.yml"))
	for _, want := range []string{"name: photon-socks5", "socks-main:", "socks-cn:", "h2:", "metacubex/mihomo:v1.19.34", "ipv6_address: fd42:1::20", "ipv6_address: fd42:1::21", "./config/socks.yaml:/etc/mihomo/config.yaml:ro", "./config/h2.yaml:/etc/mihomo/config.yaml:ro"} {
		if !strings.Contains(serviceCompose, want) {
			t.Fatalf("service compose missing %q:\n%s", want, serviceCompose)
		}
	}
	var compose composeFile
	if err := yaml.Unmarshal([]byte(serviceCompose), &compose); err != nil {
		t.Fatalf("decode service compose: %v", err)
	}
	for _, network := range []string{"main", "cn"} {
		service, ok := compose.Services["socks-"+network]
		if !ok {
			t.Fatalf("service compose missing socks-%s: %+v", network, compose.Services)
		}
		if len(service.Networks) != 1 {
			t.Fatalf("socks-%s networks = %+v, want one isolated attachment", network, service.Networks)
		}
		if _, ok := service.Networks[network]; !ok {
			t.Fatalf("socks-%s attached to %+v, want %s", network, service.Networks, network)
		}
	}
	if _, ok := compose.Services["socks"]; ok {
		t.Fatalf("service compose retained multi-network socks container: %+v", compose.Services["socks"])
	}
	if strings.Contains(serviceCompose, "ports:") {
		t.Fatalf("service compose unexpectedly publishes host ports:\n%s", serviceCompose)
	}
	if strings.Contains(serviceCompose, "\n    dns:") || strings.Contains(serviceCompose, "depends_on:") {
		t.Fatalf("service compose still contains SmartDNS dependency:\n%s", serviceCompose)
	}
	socksConfig := readTestFile(t, filepath.Join(output, "socks5", "config", "socks.yaml"))
	for _, want := range []string{"name: photon-socks", "listen: '::'", "port: 3128", "type: socks", "users: []", "udp: true", "ip-version: ipv4-prefer"} {
		if !strings.Contains(socksConfig, want) {
			t.Fatalf("SOCKS Mihomo config missing %q:\n%s", want, socksConfig)
		}
	}
	if strings.Contains(socksConfig, "auth:") {
		t.Fatalf("SOCKS5 must remain NO AUTH:\n%s", socksConfig)
	}
	h2Config := readTestFile(t, filepath.Join(output, "socks5", "config", "h2.yaml"))
	for _, want := range []string{"name: photon-http", "type: http", "users:", "username: photon", "password: 2a0d", "ip-version: ipv4-prefer"} {
		if !strings.Contains(h2Config, want) {
			t.Fatalf("legacy HTTP Mihomo config missing %q:\n%s", want, h2Config)
		}
	}
	if strings.Contains(h2Config, "udp:") {
		t.Fatalf("HTTP config unexpectedly enables SOCKS5 UDP:\n%s", h2Config)
	}
	if info, err := os.Stat(filepath.Join(output, "socks5", "config", "h2.yaml")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("H2 config mode = %v, %v; want 0600", info, err)
	}
}

func TestResolveAndRenderNetworkOnlyManifest(t *testing.T) {
	output := t.TempDir()
	configured := manifest{
		Version:   1,
		OutputDir: output,
		Images:    imageConfig{Gost: defaultGostImage},
		Networks: map[string]networkConfig{
			"main": {IPv6: "assignment:fd42:1::/64;::/112;::100/120;::1"},
		},
	}

	resolved, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err != nil {
		t.Fatalf("resolveManifest: %v", err)
	}
	if resolved.SOCKS5.configured() {
		t.Fatalf("network-only manifest unexpectedly configured SOCKS5: %#v", resolved.SOCKS5)
	}
	resolved.ManagedZone = "node-a.catofes."
	if err := renderArtifacts(resolved); err != nil {
		t.Fatalf("renderArtifacts: %v", err)
	}

	networkCompose := readTestFile(t, filepath.Join(output, "networks", "docker-compose.yml"))
	for _, want := range []string{"name: photon-networks", "name: photon-main", "fd42:1::/112"} {
		if !strings.Contains(networkCompose, want) {
			t.Fatalf("network compose missing %q:\n%s", want, networkCompose)
		}
	}
	if strings.Contains(networkCompose, "gateway_mode_ipv6: nat-unprotected") {
		t.Fatalf("network-only compose unexpectedly used a SOCKS5 gateway mode:\n%s", networkCompose)
	}
	if _, err := os.Stat(filepath.Join(output, "socks5", "docker-compose.yml")); !os.IsNotExist(err) {
		t.Fatalf("network-only render created SOCKS5 compose: %v", err)
	}
	if err := publishResolvedService("photon", resolved); err == nil || !strings.Contains(err.Error(), "does not configure socks5") {
		t.Fatalf("network-only publish error = %v", err)
	}
}

func TestResolveManifestRejectsInvalidTrustedHostInterface(t *testing.T) {
	configured := manifest{
		Version: 1, OutputDir: t.TempDir(), Images: imageConfig{Gost: defaultGostImage},
		Networks: map[string]networkConfig{"main": {
			IPv6: "assignment:fd42:1::/64;::/112;::100/120;::1", TrustedHostInterfaces: []string{"phx0:eth0"},
		}},
		SOCKS5: socks5Config{Publish: publishConfig{"main": "test"}, Networks: map[string]string{"main": "::20"}},
	}
	_, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err == nil || !strings.Contains(err.Error(), "trusted_host_interfaces") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveManifestAppliesAndOverridesNetworkDefaults(t *testing.T) {
	configured := manifest{
		Version: 1, OutputDir: t.TempDir(), Images: imageConfig{Gost: defaultGostImage},
		NetworkDefaults: networkDefaults{TrustedHostInterfaces: []string{"phv2mesh"}},
		Networks: map[string]networkConfig{
			"main": {IPv6: "assignment:fd42:1::/64;::/112;::100/120;::1"},
			"cn": {
				IPv6:                  "assignment:fd42:2::/64;::/112;::100/120;::1",
				TrustedHostInterfaces: []string{"phx0"},
			},
		},
		SOCKS5: socks5Config{
			Publish:  publishConfig{"main": "local", "cn": "cn"},
			Networks: map[string]string{"main": "::20", "cn": "::20"},
		},
	}
	resolved, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}, {Prefix: "fd42:2::/64"}})
	if err != nil {
		t.Fatalf("resolveManifest: %v", err)
	}
	if got := strings.Join(resolved.Networks["main"].TrustedHostInterfaces, ","); got != "phv2mesh" {
		t.Fatalf("main trusted interfaces = %q, want inherited phv2mesh", got)
	}
	if got := strings.Join(resolved.Networks["cn"].TrustedHostInterfaces, ","); got != "phx0" {
		t.Fatalf("cn trusted interfaces = %q, want override phx0", got)
	}
}

func TestComposeBridgeDriverOptsUsesServiceAddressFamily(t *testing.T) {
	for _, test := range []struct {
		name       string
		address    string
		gatewayOpt string
	}{
		{name: "IPv4", address: "172.30.0.20", gatewayOpt: "com.docker.network.bridge.gateway_mode_ipv4"},
		{name: "IPv6", address: "fd42::20", gatewayOpt: "com.docker.network.bridge.gateway_mode_ipv6"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := composeBridgeDriverOpts([]string{"phv2mesh"}, test.address)
			if options["com.docker.network.bridge.trusted_host_interfaces"] != "phv2mesh" {
				t.Fatalf("driver options = %#v", options)
			}
			if options[test.gatewayOpt] != "nat-unprotected" || len(options) != 2 {
				t.Fatalf("driver options = %#v", options)
			}
		})
	}
}

func TestPublishedServiceAddressExcludesAttachedUnpublishedNetwork(t *testing.T) {
	service := resolvedSOCKS5{
		Networks: map[string]resolvedRoleAddrs{
			"main":  {SOCKS: "fd42:1::20"},
			"admin": {SOCKS: "fd42:2::20"},
		},
		Endpoints: []resolvedEndpoint{{Network: "main", Address: "fd42:1::20"}},
	}
	if got := publishedServiceAddress(service, "main"); got != "fd42:1::20" {
		t.Fatalf("published address = %q", got)
	}
	if got := publishedServiceAddress(service, "admin"); got != "" {
		t.Fatalf("unpublished address = %q, want empty", got)
	}
}

func TestResolveManifestRejectsDynamicRoleAddress(t *testing.T) {
	configured := manifest{
		Version: 1, OutputDir: t.TempDir(), Images: imageConfig{Gost: defaultGostImage},
		Networks: map[string]networkConfig{"main": {IPv6: "assignment:fd42:1::/64;::/112;::100/120;::1"}},
		SOCKS5:   socks5Config{Publish: publishConfig{"main": "test"}, Networks: map[string]string{"main": "::100"}},
	}
	_, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err == nil || !strings.Contains(err.Error(), "dynamic range") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveManifestPublishesAutoAndTaggedSharedEndpoints(t *testing.T) {
	configured := manifest{
		Version: 1, OutputDir: t.TempDir(), Images: imageConfig{Gost: defaultGostImage},
		Networks: map[string]networkConfig{
			"node": {IPv6: "auto;::/112;::100/120;::1"},
			"cn":   {IPv6: "tag:socks5.cn;::/112;::100/120;::1"},
		},
		SOCKS5: socks5Config{
			Publish:  publishConfig{"node": "local", "cn": "cn"},
			Networks: map[string]string{"node": "::20", "cn": "::20"},
		},
	}
	resolved, err := resolveManifest(configured, []runtimeAssignment{
		{Prefix: "fd42:1::/64"},
		{Prefix: "fd42:2::/96", Shared: true, Tag: "socks5.cn"},
	})
	if err != nil {
		t.Fatalf("resolveManifest: %v", err)
	}
	if len(resolved.SOCKS5.Endpoints) != 2 {
		t.Fatalf("endpoints = %+v", resolved.SOCKS5.Endpoints)
	}
	if endpoint := resolved.SOCKS5.Endpoints[0]; endpoint.Network != "cn" || !endpoint.Shared || endpoint.Assignment != "fd42:2::/96" {
		t.Fatalf("cn endpoint = %+v", endpoint)
	}
	if !serviceControlsRoute(resolved.SOCKS5.Endpoints[0]) || serviceControlsRoute(resolved.SOCKS5.Endpoints[1]) {
		t.Fatalf("route ownership should be shared-only: %+v", resolved.SOCKS5.Endpoints)
	}
}

func TestResolveManifestRejectsPublishNetworkWithOversizedACLName(t *testing.T) {
	name := strings.Repeat("a", 63)
	configured := manifest{
		Version: 1, OutputDir: t.TempDir(), Images: imageConfig{Gost: defaultGostImage},
		Networks: map[string]networkConfig{name: {IPv6: "auto;::/112;::100/120;::1"}},
		SOCKS5: socks5Config{
			Publish:  publishConfig{name: "local"},
			Networks: map[string]string{name: "::20"},
		},
	}
	_, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("error = %v", err)
	}
}

func TestNormalizeHTTPAuth(t *testing.T) {
	if got, err := normalizeHTTPAuth(proxyAuthConfig{}); err != nil || got.Username != "photon" || got.Password != "2a0d" {
		t.Fatalf("default HTTP auth = %#v, %v", got, err)
	}
	custom := proxyAuthConfig{Username: "proxy", Password: "secret"}
	if got, err := normalizeHTTPAuth(custom); err != nil || got != custom {
		t.Fatalf("custom HTTP auth = %#v, %v", got, err)
	}
	for _, invalid := range []proxyAuthConfig{
		{Username: "proxy"},
		{Password: "secret"},
		{Username: "proxy\nadmin", Password: "secret"},
	} {
		if _, err := normalizeHTTPAuth(invalid); err == nil {
			t.Fatalf("accepted invalid HTTP auth %#v", invalid)
		}
	}
}

func TestNormalizeResolver(t *testing.T) {
	for _, test := range []struct {
		name       string
		configured resolverConfig
		wantMode   string
		wantServer string
		wantError  string
	}{
		{name: "defaults", wantMode: "ipv4_first", wantServer: "8.8.8.8,1.1.1.1"},
		{name: "IPv4 only", configured: resolverConfig{Mode: "ipv4_only", Servers: []string{"9.9.9.9", "9.9.9.9"}}, wantMode: "ipv4_only", wantServer: "9.9.9.9"},
		{name: "invalid mode", configured: resolverConfig{Mode: "fastest"}, wantError: "unsupported mode"},
		{name: "empty server", configured: resolverConfig{Servers: []string{" "}}, wantError: "single-line"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := normalizeResolver(test.configured)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if resolved.Mode != test.wantMode || strings.Join(resolved.Servers, ",") != test.wantServer {
				t.Fatalf("resolver = %#v", resolved)
			}
		})
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
