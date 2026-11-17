package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func mihomoImage(images imageConfig) string {
	if images.Mihomo != "" {
		return images.Mihomo
	}
	return defaultMihomoImage
}

func mihomoService(images imageConfig, attachments map[string]composeServiceAttachment, config string) composeService {
	return composeService{Image: mihomoImage(images), Restart: "unless-stopped", Networks: attachments,
		Command: []string{"-d", "/etc/mihomo", "-f", "/etc/mihomo/config.yaml"},
		Volumes: []string{config + ":/etc/mihomo/config.yaml:ro"}}
}

func mihomoProxyConfig(resolver resolverConfig, listener map[string]any) map[string]any {
	preference := map[string]string{"ipv4_first": "ipv4-prefer", "ipv6_first": "ipv6-prefer", "ipv4_only": "ipv4", "ipv6_only": "ipv6"}[resolver.Mode]
	return map[string]any{
		"mode": "rule", "log-level": "info", "ipv6": true,
		"dns":       map[string]any{"enable": true, "ipv6": resolver.Mode != "ipv4_only", "nameserver": resolver.Servers},
		"listeners": []any{listener},
		"proxies":   []any{map[string]any{"name": "photon-egress", "type": "direct", "ip-version": preference}},
		"rules":     []string{"MATCH,photon-egress"},
	}
}

func plainMihomoConfig(kind string, port uint16, resolver resolverConfig, auth proxyAuthConfig) map[string]any {
	listener := map[string]any{"name": "photon-" + kind, "type": kind, "listen": "::", "port": port, "users": []any{}}
	if kind == "socks" {
		listener["udp"] = true
	}
	if auth.Username != "" {
		listener["users"] = []any{map[string]string{"username": auth.Username, "password": auth.Password}}
	}
	return mihomoProxyConfig(resolver, listener)
}

func renderSOCKS5Compose(manifest resolvedManifest, service resolvedSOCKS5) error {
	dir := filepath.Join(manifest.OutputDir, "socks5")
	compose := composeFile{Name: "photon-socks5", Services: map[string]composeService{}, Networks: map[string]composeNetwork{}}
	legacyHTTP := map[string]composeServiceAttachment{}
	for _, endpoint := range service.Endpoints {
		compose.Networks[endpoint.Network] = composeNetwork{Name: manifest.Networks[endpoint.Network].Name, External: true}
		// One endpoint per process keeps UDP replies on the advertised address.
		compose.Services["socks-"+endpoint.Network] = mihomoService(manifest.Images, map[string]composeServiceAttachment{endpoint.Network: attachmentForAddress(endpoint.Address)}, "./config/socks.yaml")
	}
	for id, roles := range service.Networks {
		if roles.H2 != "" {
			compose.Networks[id] = composeNetwork{Name: manifest.Networks[id].Name, External: true}
			legacyHTTP[id] = attachmentForAddress(roles.H2)
		}
	}
	// v1 retains its old project/service names for existing deployment units.
	// v2 never implicitly creates HTTP and uses its own photon-http project.
	if len(legacyHTTP) != 0 {
		compose.Services["h2"] = mihomoService(manifest.Images, legacyHTTP, "./config/h2.yaml")
		if err := writeYAMLMode(filepath.Join(dir, "config", "h2.yaml"), plainMihomoConfig("http", service.Port, service.Resolver, service.HTTPAuth), 0600); err != nil {
			return err
		}
	}
	if err := writeYAML(filepath.Join(dir, "docker-compose.yml"), compose); err != nil {
		return err
	}
	if err := writeYAMLMode(filepath.Join(dir, "config", "socks.yaml"), plainMihomoConfig("socks", service.Port, service.Resolver, proxyAuthConfig{}), 0600); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "config", "smartdns.conf")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return writeSOCKS5Lock(filepath.Join(dir, "resolved.json"), renderedSOCKS5Lock{resolvedSOCKS5: service, ManagedZone: manifest.ManagedZone})
}

type httpLock struct {
	resolvedHTTP
	ManagedZone string `json:"managed_zone"`
}

func renderHTTP(manifest resolvedManifest) error {
	dir := filepath.Join(manifest.OutputDir, "http")
	service := manifest.HTTP
	compose := composeFile{Name: "photon-http", Services: map[string]composeService{}, Networks: map[string]composeNetwork{}}
	for _, endpoint := range service.Endpoints {
		compose.Networks[endpoint.Network] = composeNetwork{Name: manifest.Networks[endpoint.Network].Name, External: true}
		compose.Services["http-"+endpoint.Network] = mihomoService(manifest.Images, map[string]composeServiceAttachment{endpoint.Network: attachmentForAddress(endpoint.Address)}, "./config.yaml")
	}
	if err := writeYAML(filepath.Join(dir, "docker-compose.yml"), compose); err != nil {
		return err
	}
	if err := writeYAMLMode(filepath.Join(dir, "config.yaml"), plainMihomoConfig("http", service.Port, service.Resolver, service.Auth), 0600); err != nil {
		return err
	}
	return writeHTTPLock(filepath.Join(dir, "resolved.json"), httpLock{resolvedHTTP: service, ManagedZone: manifest.ManagedZone})
}

func writeHTTPLock(path string, lock httpLock) error {
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0644)
}
