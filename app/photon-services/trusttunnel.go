package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	service "github.com/HiggsNet/photon/pkg/service"
)

const defaultMihomoImage = "metacubex/mihomo:v1.19.34"
const trustTunnelCongestionController = "bbr"

type trustTunnelConfig struct {
	Publish    publishConfig     `yaml:"publish"`
	Networks   map[string]string `yaml:"networks"`
	Port       uint16            `yaml:"port,omitempty"`
	AllowZones []string          `yaml:"allow_zones"`
	Resolver   resolverConfig    `yaml:"resolver,omitempty"`
}

func (c trustTunnelConfig) configured() bool {
	return len(c.Publish) != 0 || len(c.Networks) != 0 || c.Port != 0 || len(c.AllowZones) != 0 || c.Resolver.Mode != "" || len(c.Resolver.Servers) != 0
}

type resolvedTrustTunnel struct {
	Port       uint16             `json:"port"`
	AllowZones []string           `json:"allow_zones"`
	Resolver   resolverConfig     `json:"resolver"`
	ConfigHash string             `json:"config_hash"`
	Endpoints  []resolvedEndpoint `json:"endpoints"`
}

func (s resolvedTrustTunnel) configured() bool { return s.ConfigHash != "" }

type trustTunnelLock struct {
	resolvedTrustTunnel
	ManagedZone string `json:"managed_zone"`
	ServerName  string `json:"server_name"`
	Fingerprint string `json:"fingerprint"`
}

func resolveTrustTunnel(config trustTunnelConfig, networks map[string]resolvedNetwork) (resolvedTrustTunnel, error) {
	if len(config.Publish) == 0 || len(config.Networks) == 0 {
		return resolvedTrustTunnel{}, errors.New("trusttunnel.publish and networks are required")
	}
	if config.Port == 0 {
		config.Port = 4433
	}
	if len(config.AllowZones) == 0 {
		return resolvedTrustTunnel{}, errors.New("trusttunnel.allow_zones must explicitly authorize access")
	}
	result := resolvedTrustTunnel{Port: config.Port}
	for _, raw := range config.AllowZones {
		selector, err := service.ParseZoneSelector(raw)
		if err != nil {
			return result, err
		}
		result.AllowZones = append(result.AllowZones, selector.String())
	}
	resolver, err := normalizeResolver(config.Resolver)
	if err != nil {
		return result, err
	}
	result.Resolver = resolver
	for name, region := range config.Publish {
		if region != "local" {
			return result, errors.New("trusttunnel only publishes fixed local endpoints")
		}
		if len("trusttunnel-"+name) > 63 {
			return result, errors.New("trusttunnel network name is too long")
		}
		network, ok := networks[name]
		if !ok {
			return result, fmt.Errorf("trusttunnel: unknown network %q", name)
		}
		raw, ok := config.Networks[name]
		if !ok {
			return result, fmt.Errorf("trusttunnel: publish network %q is not attached", name)
		}
		address, ipam, err := resolveServiceBase(raw, network)
		if err != nil {
			return result, err
		}
		if ipam.Assignment == "" || ipam.Shared {
			return result, errors.New("trusttunnel requires a non-shared IPAM assignment")
		}
		subnet, dynamic := netip.MustParsePrefix(ipam.Subnet), netip.MustParsePrefix(ipam.IPRange)
		if !subnet.Contains(address) || address == subnet.Addr() || (address.Is4() && !subnet.Contains(address.Next())) || dynamic.Contains(address) || address.String() == ipam.Gateway {
			return result, errors.New("trusttunnel address conflicts with subnet, gateway or dynamic range")
		}
		result.Endpoints = append(result.Endpoints, resolvedEndpoint{Network: name, Region: region, Address: address.String(), Port: config.Port, Assignment: ipam.Assignment})
	}
	for name := range config.Networks {
		if _, ok := config.Publish[name]; !ok {
			return result, fmt.Errorf("trusttunnel network %q is not published", name)
		}
	}
	sort.Slice(result.Endpoints, func(i, j int) bool { return result.Endpoints[i].Network < result.Endpoints[j].Network })
	encoded, _ := json.Marshal(struct {
		Config   trustTunnelConfig
		Networks map[string]resolvedNetwork
	}{config, networks})
	hash := sha256.Sum256(encoded)
	result.ConfigHash = hex.EncodeToString(hash[:])
	return result, nil
}

func trustTunnelServerName(zone string) string { return "trusttunnel." + strings.TrimSuffix(zone, ".") }

// A node certificate is created once and reused across render/restarts. It is
// authenticated by the signed directory pin rather than by a public CA.
func ensureTrustTunnelCertificate(dir, name string) (string, error) {
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return "", err
		}
		now := time.Now()
		cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			return "", err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		}
		if err := atomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
			return "", err
		}
		if err := atomicWrite(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return "", err
		}
	} else if certErr != nil || keyErr != nil {
		return "", fmt.Errorf("trusttunnel certificate/key must both exist: %v / %v", certErr, keyErr)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", err
	}
	if err := cert.VerifyHostname(name); err != nil {
		return "", err
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return "", errors.New("trusttunnel certificate is not currently valid")
	}
	hash := sha256.Sum256(pair.Certificate[0])
	return hex.EncodeToString(hash[:]), nil
}

func renderTrustTunnel(manifest resolvedManifest) error {
	s := manifest.TrustTunnel
	dir := filepath.Join(manifest.OutputDir, "trusttunnel")
	name := trustTunnelServerName(manifest.ManagedZone)
	var endpoints []service.SOCKS5Endpoint
	for _, endpoint := range s.Endpoints {
		endpoints = append(endpoints, service.SOCKS5Endpoint{Region: endpoint.Region, Address: endpoint.Address, Port: endpoint.Port})
	}
	if err := (service.TrustTunnelRecord{Type: service.TypeTrustTunnel, Endpoints: endpoints, ServerName: name, Fingerprint: strings.Repeat("0", 64)}).Validate(); err != nil {
		return err
	}
	fingerprint, err := ensureTrustTunnelCertificate(filepath.Join(dir, "tls"), name)
	if err != nil {
		return err
	}
	compose := composeFile{Name: "photon-trusttunnel", Services: map[string]composeService{}, Networks: map[string]composeNetwork{}}
	image := manifest.Images.Mihomo
	if image == "" {
		image = defaultMihomoImage
	}
	for _, endpoint := range s.Endpoints {
		compose.Networks[endpoint.Network] = composeNetwork{Name: manifest.Networks[endpoint.Network].Name, External: true}
		compose.Services[endpoint.Network] = composeService{
			Image:    image,
			Restart:  "unless-stopped",
			Networks: map[string]composeServiceAttachment{endpoint.Network: attachmentForAddress(endpoint.Address)},
			Command:  []string{"-d", "/etc/mihomo", "-f", "/etc/mihomo/config.yaml"},
			Volumes:  []string{"./config.yaml:/etc/mihomo/config.yaml:ro", "./tls:/etc/mihomo/tls:ro"},
			// Compose recreates the service when the algorithm in the mounted config changes.
			Labels: map[string]string{"io.photon.trusttunnel.congestion-controller": trustTunnelCongestionController},
		}
	}
	if err := writeYAML(filepath.Join(dir, "docker-compose.yml"), compose); err != nil {
		return err
	}
	config := mihomoProxyConfig(s.Resolver, map[string]any{
		"name":                  "photon-trusttunnel",
		"type":                  "trusttunnel",
		"listen":                "::",
		"port":                  s.Port,
		"network":               []string{"udp"},
		"certificate":           "/etc/mihomo/tls/server.crt",
		"private-key":           "/etc/mihomo/tls/server.key",
		"users":                 []any{map[string]string{"username": service.TrustTunnelUser, "password": ""}},
		"congestion-controller": trustTunnelCongestionController,
	})
	if err := writeYAMLMode(filepath.Join(dir, "config.yaml"), config, 0o600); err != nil {
		return err
	}
	return writeTrustTunnelLock(filepath.Join(dir, "resolved.json"), trustTunnelLock{resolvedTrustTunnel: s, ManagedZone: manifest.ManagedZone, ServerName: name, Fingerprint: fingerprint})
}

func loadTrustTunnelLock(dir, file string) (trustTunnelLock, error) {
	var lock trustTunnelLock
	data, err := os.ReadFile(filepath.Join(dir, "trusttunnel", file))
	if err != nil {
		return lock, err
	}
	err = json.Unmarshal(data, &lock)
	return lock, err
}
func writeTrustTunnelLock(path string, lock trustTunnelLock) error {
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0o644)
}

// curl's HTTP/3-only request verifies QUIC, certificate and the authenticated
// TrustTunnel health stream. It must not silently fall back to HTTP/2/TCP.
func checkTrustTunnelHTTP3(endpoint resolvedEndpoint, name, certPath string) error {
	address := endpoint.Address
	if strings.Contains(address, ":") {
		address = "[" + address + "]"
	}
	resolve := fmt.Sprintf("%s:%d:%s", name, endpoint.Port, address)
	auth := base64.StdEncoding.EncodeToString([]byte(service.TrustTunnelUser + ":"))
	cmd := exec.Command("curl", "--noproxy", "*", "--http3-only", "--silent", "--show-error", "--fail", "--connect-timeout", "5", "--max-time", "8", "--cacert", certPath, "--resolve", resolve, "--request", "CONNECT", "--request-target", "_check", "--header", "Proxy-Authorization: Basic "+auth, "--output", os.DevNull, "--write-out", "%{http_code} %{http_version}", fmt.Sprintf("https://%s:%d/", name, endpoint.Port))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trusttunnel HTTP/3 readiness: %w: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "200 3" {
		return fmt.Errorf("trusttunnel readiness requires HTTP/3 200, got %q", out)
	}
	return nil
}

func publishTrustTunnel(photon string, manifest resolvedManifest) error {
	return publishTrustTunnelWithProbe(photon, manifest, func(endpoint resolvedEndpoint, name, cert string, resolver resolverConfig) error {
		if err := checkTrustTunnelHTTP3(endpoint, name, cert); err != nil {
			return err
		}
		return checkTrustTunnelUDPDNS(endpoint, name, cert, resolver)
	})
}

func publishTrustTunnelWithProbe(photon string, manifest resolvedManifest, probe func(resolvedEndpoint, string, string, resolverConfig) error) error {
	lock, err := loadTrustTunnelLock(manifest.OutputDir, "resolved.json")
	if err != nil {
		return err
	}
	s := manifest.TrustTunnel
	if lock.ConfigHash != s.ConfigHash || lock.ManagedZone != manifest.ManagedZone || !reflect.DeepEqual(lock.Endpoints, s.Endpoints) {
		return errors.New("trusttunnel assignment or config changed; run render again")
	}
	dir := filepath.Join(manifest.OutputDir, "trusttunnel")
	name := trustTunnelServerName(manifest.ManagedZone)
	fingerprint, err := ensureTrustTunnelCertificate(filepath.Join(dir, "tls"), name)
	if err != nil {
		return err
	}
	if lock.ServerName != name || lock.Fingerprint != fingerprint {
		return errors.New("trusttunnel TLS identity changed; run render again")
	}
	for _, endpoint := range s.Endpoints {
		if err := probe(endpoint, name, filepath.Join(dir, "tls", "server.crt"), s.Resolver); err != nil {
			return err
		}
	}
	for _, endpoint := range s.Endpoints {
		args := []string{"firewall", "endpoint", "apply", "trusttunnel-" + endpoint.Network, "--destination", endpoint.Address, "--scope", "ip"}
		for _, selector := range s.AllowZones {
			args = append(args, "--allow-zone", selector)
		}
		if err := runPhoton(photon, args...); err != nil {
			return err
		}
	}
	args := []string{"service", "publish", "--type", "trusttunnel", "--server-name", name, "--fingerprint", fingerprint}
	for _, endpoint := range s.Endpoints {
		args = append(args, "--endpoint", fmt.Sprintf("%s,%s,%d", endpoint.Region, endpoint.Address, endpoint.Port))
	}
	if err := runPhoton(photon, args...); err != nil {
		return err
	}
	previous, err := loadTrustTunnelLock(manifest.OutputDir, "published.json")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, old := range previous.Endpoints {
		found := false
		for _, current := range s.Endpoints {
			if current.Network == old.Network {
				found = true
			}
		}
		if !found {
			if err := runPhoton(photon, "firewall", "endpoint", "remove", "trusttunnel-"+old.Network); err != nil {
				return err
			}
		}
	}
	return writeTrustTunnelLock(filepath.Join(dir, "published.json"), lock)
}

func withdrawTrustTunnel(photon, dir string) error {
	lock, err := loadTrustTunnelLock(dir, "published.json")
	if err != nil {
		return err
	}
	if err := runPhoton(photon, "service", "withdraw", "--type", "trusttunnel"); err != nil {
		return err
	}
	for _, endpoint := range lock.Endpoints {
		if err := runPhoton(photon, "firewall", "endpoint", "remove", "trusttunnel-"+endpoint.Network); err != nil {
			return err
		}
	}
	lock.Endpoints = nil
	return writeTrustTunnelLock(filepath.Join(dir, "trusttunnel", "published.json"), lock)
}
