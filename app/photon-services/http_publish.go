package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

func checkHTTPProxy(endpoint resolvedEndpoint, auth proxyAuthConfig, target string) error {
	proxy := &url.URL{Scheme: "http", Host: net.JoinHostPort(endpoint.Address, fmt.Sprint(endpoint.Port))}
	if auth.Username != "" {
		proxy.User = url.UserPassword(auth.Username, auth.Password)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("http proxy readiness: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("http proxy readiness returned %s", response.Status)
	}
	return nil
}

func loadHTTPLock(output, file string) (httpLock, error) {
	var lock httpLock
	data, err := os.ReadFile(filepath.Join(output, "http", file))
	if err != nil {
		return lock, err
	}
	err = json.Unmarshal(data, &lock)
	return lock, err
}

func publishHTTP(photon string, manifest resolvedManifest) error {
	return publishHTTPWithProbe(photon, manifest, func(e resolvedEndpoint, a proxyAuthConfig) error {
		return checkHTTPProxy(e, a, "https://www.gstatic.com/generate_204")
	})
}

func publishHTTPWithProbe(photon string, manifest resolvedManifest, probe func(resolvedEndpoint, proxyAuthConfig) error) error {
	lock, err := loadHTTPLock(manifest.OutputDir, "resolved.json")
	if err != nil {
		return err
	}
	s := manifest.HTTP
	if lock.ConfigHash != s.ConfigHash || lock.ManagedZone != manifest.ManagedZone || !reflect.DeepEqual(lock.Endpoints, s.Endpoints) {
		return errors.New("http assignment or config changed; run render again")
	}
	for _, e := range s.Endpoints {
		if err := probe(e, s.Auth); err != nil {
			return err
		}
	}
	for _, e := range s.Endpoints {
		if len(s.AllowZones) > 0 {
			args := []string{"firewall", "endpoint", "apply", "http-" + e.Network, "--destination", e.Address, "--scope", "ip"}
			for _, zone := range s.AllowZones {
				args = append(args, "--allow-zone", zone)
			}
			if err := runPhoton(photon, args...); err != nil {
				return err
			}
		} else if err := runPhoton(photon, "firewall", "endpoint", "remove", "http-"+e.Network); err != nil {
			return err
		}
		if e.Shared {
			if err := runPhoton(photon, "route", "announce", manifest.ManagedZone, e.Assignment); err != nil {
				return err
			}
		}
	}
	args := []string{"service", "publish", "--type", "http"}
	if s.Auth.Username != "" {
		args = append(args, "--auth-required")
	}
	for _, e := range s.Endpoints {
		args = append(args, "--endpoint", fmt.Sprintf("%s,%s,%d", e.Region, e.Address, e.Port))
	}
	if err := runPhoton(photon, args...); err != nil {
		return err
	}
	previous, err := loadHTTPLock(manifest.OutputDir, "published.json")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, old := range previous.Endpoints {
		if endpointStillPublished(old, s.Endpoints) {
			continue
		}
		if old.Shared && !manifestUsesSharedRoute(manifest, old.Assignment) {
			if err := runPhoton(photon, "route", "withdraw", previous.ManagedZone, old.Assignment); err != nil {
				return err
			}
		}
		// Reusing the same ACL name replaces its destination during apply.
		found := false
		for _, e := range s.Endpoints {
			if e.Network == old.Network {
				found = true
			}
		}
		if !found {
			if err := runPhoton(photon, "firewall", "endpoint", "remove", "http-"+old.Network); err != nil {
				return err
			}
		}
	}
	return writeHTTPLock(filepath.Join(manifest.OutputDir, "http", "published.json"), lock)
}

func manifestUsesSharedRoute(manifest resolvedManifest, prefix string) bool {
	for _, endpoints := range [][]resolvedEndpoint{manifest.SOCKS5.Endpoints, manifest.HTTP.Endpoints} {
		for _, e := range endpoints {
			if e.Shared && e.Assignment == prefix {
				return true
			}
		}
	}
	return false
}

// Published locks, rather than newly edited enable flags, own withdrawal.
// Remove a shared prefix once, after all its service records are withdrawn.
func withdrawServices(photon string, manifest manifest) error {
	output := manifest.OutputDir
	var socks renderedSOCKS5Lock
	if data, err := os.ReadFile(filepath.Join(output, "socks5", "published.json")); err == nil {
		if err := json.Unmarshal(data, &socks); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	httpLock, err := loadHTTPLock(output, "published.json")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tt, err := loadTrustTunnelLock(output, "published.json")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(socks.Endpoints)+len(httpLock.Endpoints)+len(tt.Endpoints) == 0 {
		return nil
	}
	if len(tt.Endpoints) > 0 {
		if err := withdrawTrustTunnel(photon, output); err != nil {
			return err
		}
	}
	if len(httpLock.Endpoints) > 0 {
		if err := runPhoton(photon, "service", "withdraw", "--type", "http"); err != nil {
			return err
		}
	}
	if len(socks.Endpoints) > 0 {
		if err := runPhoton(photon, "service", "withdraw"); err != nil {
			return err
		}
	}
	routes := map[string]string{}
	for _, e := range socks.Endpoints {
		if err := runPhoton(photon, "firewall", "endpoint", "remove", endpointACLName(e.Network)); err != nil {
			return err
		}
		if socks.Networks[e.Network].H2 != "" {
			if err := runPhoton(photon, "firewall", "endpoint", "remove", httpEndpointACLName(e.Network)); err != nil {
				return err
			}
		}
		if e.Shared {
			routes[e.Assignment] = socks.ManagedZone
		}
	}
	for _, e := range httpLock.Endpoints {
		if err := runPhoton(photon, "firewall", "endpoint", "remove", "http-"+e.Network); err != nil {
			return err
		}
		if e.Shared {
			routes[e.Assignment] = httpLock.ManagedZone
		}
	}
	for _, prefix := range sortedKeys(routes) {
		if err := runPhoton(photon, "route", "withdraw", routes[prefix], prefix); err != nil {
			return err
		}
	}
	if len(socks.Endpoints) > 0 {
		socks.Endpoints = nil
		if err := writeSOCKS5Lock(filepath.Join(output, "socks5", "published.json"), socks); err != nil {
			return err
		}
	}
	if len(httpLock.Endpoints) > 0 {
		httpLock.Endpoints = nil
		if err := writeHTTPLock(filepath.Join(output, "http", "published.json"), httpLock); err != nil {
			return err
		}
	}
	return nil
}
