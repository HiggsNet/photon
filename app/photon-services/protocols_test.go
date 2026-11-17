package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func threeProxyFixture(t *testing.T) manifest {
	t.Helper()
	return manifest{Version: 2, OutputDir: t.TempDir(), Networks: map[string]networkConfig{"main": {IPv6: "auto;::/112;::100/120;::1"}},
		SOCKS5:      socks5Config{Networks: map[string]string{"main": "::20"}, Publish: publishConfig{"main": "local"}, AllowZones: []string{"*.catofes."}},
		HTTP:        &httpConfig{Networks: map[string]string{"main": "::21"}, Publish: publishConfig{"main": "local"}, AllowZones: []string{"*.catofes."}},
		TrustTunnel: trustTunnelConfig{Networks: map[string]string{"main": "::22"}, Publish: publishConfig{"main": "local"}, AllowZones: []string{"*.catofes."}},
	}
}

func TestProxyProtocolsEnableIndependently(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		v := threeProxyFixture(t)
		if mask&1 == 0 {
			v.SOCKS5 = socks5Config{}
		}
		if mask&2 == 0 {
			v.HTTP = nil
		}
		if mask&4 == 0 {
			v.TrustTunnel = trustTunnelConfig{}
		}
		resolved, err := resolveManifest(v, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
		if err != nil {
			t.Fatalf("combination %d: %v", mask, err)
		}
		resolved.ManagedZone = "node.catofes."
		if err := renderArtifacts(resolved); err != nil {
			t.Fatal(err)
		}
		for i, kind := range []string{"socks5", "http", "trusttunnel"} {
			path := filepath.Join(v.OutputDir, kind, "docker-compose.yml")
			data, err := os.ReadFile(path)
			if mask&(1<<i) == 0 {
				if !os.IsNotExist(err) {
					t.Fatalf("disabled %s generated artifacts", kind)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			var compose composeFile
			if err := yaml.Unmarshal(data, &compose); err != nil {
				t.Fatal(err)
			}
			if len(compose.Services) != 1 {
				t.Fatalf("%s creates implicit listeners: %s", kind, data)
			}
			for _, s := range compose.Services {
				if s.Image != defaultMihomoImage || len(s.Networks) != 1 {
					t.Fatalf("%s must use isolated Mihomo: %s", kind, data)
				}
			}
		}
		if mask&1 != 0 && resolved.SOCKS5.Networks["main"].H2 != "" {
			t.Fatal("v2 SOCKS5 implicitly reserved an HTTP address")
		}
	}
}

func TestProxyManifestRejectsCollisionsAndLegacyCredentials(t *testing.T) {
	for _, kind := range []string{"http", "trusttunnel", "legacy-auth"} {
		v := threeProxyFixture(t)
		switch kind {
		case "http":
			v.HTTP.Networks["main"] = "::20"
		case "trusttunnel":
			v.TrustTunnel.Networks["main"] = "::21"
		default:
			v.SOCKS5.HTTPAuth = proxyAuthConfig{Username: "private", Password: "secret"}
		}
		if _, err := resolveManifest(v, []runtimeAssignment{{Prefix: "fd42:1::/64"}}); err == nil {
			t.Fatalf("accepted invalid %s configuration", kind)
		}
	}
}

func TestHTTPProxyReadinessUsesAuthentication(t *testing.T) {
	auth := proxyAuthConfig{Username: "custom", Password: "private"}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Basic Y3VzdG9tOnByaXZhdGU=" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	port, _ := strconv.Atoi(u.Port())
	endpoint := resolvedEndpoint{Address: u.Hostname(), Port: uint16(port)}
	if err := checkHTTPProxy(endpoint, auth, "http://readiness.invalid/"); err != nil {
		t.Fatal(err)
	}
	if err := checkHTTPProxy(endpoint, proxyAuthConfig{}, "http://readiness.invalid/"); err == nil {
		t.Fatal("accepted authentication failure")
	}
}

func TestHTTPPublishAndWithdrawAfterConfigRemoval(t *testing.T) {
	v := threeProxyFixture(t)
	r, err := resolveManifest(v, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err != nil {
		t.Fatal(err)
	}
	r.ManagedZone = "node.catofes."
	r.HTTP.Auth = proxyAuthConfig{Username: "private", Password: "never-publish-this"}
	if err := renderArtifacts(r); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "calls")
	bin := writeFakePhoton(t, log)
	fail := func(resolvedEndpoint, proxyAuthConfig) error { return errors.New("not ready") }
	if err := publishHTTPWithProbe(bin, r, fail); err == nil {
		t.Fatal("published an unready HTTP proxy")
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("publication happened before readiness")
	}
	if err := publishHTTPWithProbe(bin, r, func(resolvedEndpoint, proxyAuthConfig) error { return nil }); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if !strings.Contains(string(data), "service publish --type http --auth-required --endpoint local,fd42:1::21,3128") || strings.Contains(string(data), "never-publish-this") {
		t.Fatal(string(data))
	}
	// The operator has removed HTTP from the current manifest; the old lock
	// must still be withdrawn instead of leaving a stale directory record.
	if err := withdrawServices(bin, manifest{OutputDir: v.OutputDir}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(log)
	if !strings.Contains(string(data), "service withdraw --type http") {
		t.Fatal(string(data))
	}
}

func TestProtocolSelectionDoesNotRecreateImplicitHTTP(t *testing.T) {
	v := threeProxyFixture(t)
	v.Version = 1
	if err := selectProxyServices(&v, "socks5"); err != nil {
		t.Fatal(err)
	}
	r, err := resolveManifest(v, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.HTTP.configured() || r.TrustTunnel.configured() || r.SOCKS5.Networks["main"].H2 != "" {
		t.Fatal("disabled HTTP reappeared")
	}
}

func TestHTTPUpdateKeepsOtherProxySharedRouteAndNewACL(t *testing.T) {
	v := threeProxyFixture(t)
	r, err := resolveManifest(v, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err != nil {
		t.Fatal(err)
	}
	r.ManagedZone = "node.catofes."
	old := r.HTTP
	old.Endpoints = append([]resolvedEndpoint(nil), old.Endpoints...)
	old.Endpoints[0].Shared = true
	old.Endpoints[0].Assignment = "fd42:2::/96"
	old.Endpoints[0].Address = "fd42:2::21"
	r.SOCKS5.Endpoints[0].Shared = true
	r.SOCKS5.Endpoints[0].Assignment = "fd42:2::/96"
	if err := renderArtifacts(r); err != nil {
		t.Fatal(err)
	}
	if err := writeHTTPLock(filepath.Join(v.OutputDir, "http", "published.json"), httpLock{resolvedHTTP: old, ManagedZone: r.ManagedZone}); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "calls")
	if err := publishHTTPWithProbe(writeFakePhoton(t, log), r, func(resolvedEndpoint, proxyAuthConfig) error { return nil }); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if strings.Contains(string(data), "route withdraw") || strings.Contains(string(data), "endpoint remove http-main") {
		t.Fatal("HTTP update broke another proxy's route or replaced ACL", string(data))
	}
}

func TestWithdrawalDeduplicatesSharedRouteAndCanRetry(t *testing.T) {
	v := threeProxyFixture(t)
	r, err := resolveManifest(v, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err != nil {
		t.Fatal(err)
	}
	r.ManagedZone = "node.catofes."
	for _, endpoints := range [][]resolvedEndpoint{r.SOCKS5.Endpoints, r.HTTP.Endpoints} {
		endpoints[0].Shared = true
		endpoints[0].Assignment = "fd42:1::/64"
	}
	if err := writeSOCKS5Lock(filepath.Join(v.OutputDir, "socks5", "published.json"), renderedSOCKS5Lock{resolvedSOCKS5: r.SOCKS5, ManagedZone: r.ManagedZone}); err != nil {
		t.Fatal(err)
	}
	if err := writeHTTPLock(filepath.Join(v.OutputDir, "http", "published.json"), httpLock{resolvedHTTP: r.HTTP, ManagedZone: r.ManagedZone}); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "calls")
	bin := writeFakePhoton(t, log)
	if err := withdrawServices(bin, v); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if strings.Count(string(data), "route withdraw") != 1 {
		t.Fatal("shared route withdrawn more than once", string(data))
	}
	if err := withdrawServices(bin, v); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(log)
	if string(again) != string(data) {
		t.Fatal("withdrawal retry changed already-cleared publication")
	}
}
