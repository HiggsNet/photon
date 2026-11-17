package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"
)

const defaultManifestPath = "/etc/photon/service.yaml"
const socks5ServiceName = "socks5"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: photon-services <validate|render|prepare|publish|withdraw> [options]")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := flags.String("config", defaultManifestPath, "service manifest path")
	photonBinary := flags.String("photon", "photon", "photon CLI path")
	outputDir := flags.String("output", "", "override artifact output directory")
	only := flags.String("only", "", "comma-separated protocols: http,socks5,trusttunnel; none for network-only")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if command == "withdraw" {
		if *only != "" {
			return errors.New("withdraw uses all published state; --only applies to validate/render/prepare/publish")
		}
		if flags.NArg() != 0 {
			return errors.New("usage: photon-services withdraw [options]")
		}
		manifest, err := loadManifest(*configPath)
		if err != nil {
			return err
		}
		if *outputDir != "" {
			manifest.OutputDir = *outputDir
		}
		return withdrawServices(*photonBinary, manifest)
	}
	manifest, err := loadManifest(*configPath)
	if err != nil {
		return err
	}
	if *outputDir != "" {
		manifest.OutputDir = *outputDir
	}
	if err := selectProxyServices(&manifest, *only); err != nil {
		return err
	}
	report, err := queryAssignments(*photonBinary)
	if err != nil {
		return err
	}
	resolved, err := resolveManifest(manifest, report.Assignments)
	if err != nil {
		return err
	}
	resolved.ManagedZone = report.ManagedZone
	switch command {
	case "validate":
		return writeJSON(os.Stdout, resolved)
	case "render":
		if err := renderArtifacts(resolved); err != nil {
			return err
		}
		fmt.Printf("rendered service artifacts under %s\n", resolved.OutputDir)
		return nil
	case "prepare":
		return prepareProxyACLs(*photonBinary, resolved)
	case "publish":
		if flags.NArg() != 0 {
			return errors.New("usage: photon-services publish [options]")
		}
		if resolved.SOCKS5.configured() {
			if err := publishResolvedService(*photonBinary, resolved); err != nil {
				return err
			}
		}
		if resolved.HTTP.configured() {
			if err := publishHTTP(*photonBinary, resolved); err != nil {
				return err
			}
		}
		if resolved.TrustTunnel.configured() {
			return publishTrustTunnel(*photonBinary, resolved)
		}
		if !resolved.SOCKS5.configured() && !resolved.HTTP.configured() {
			return errors.New("service manifest does not configure a proxy")
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func queryAssignments(photonBinary string) (runtimeIPAMReport, error) {
	cmd := exec.Command(photonBinary, "route", "ipam", "mine", "--json")
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return runtimeIPAMReport{}, fmt.Errorf("photon route ipam mine: %s", exit.Stderr)
		}
		return runtimeIPAMReport{}, fmt.Errorf("photon route ipam mine: %w", err)
	}
	var report runtimeIPAMReport
	if err := json.Unmarshal(out, &report); err != nil {
		return runtimeIPAMReport{}, fmt.Errorf("decode photon route ipam mine output: %w", err)
	}
	return report, nil
}

func publishResolvedService(photonBinary string, manifest resolvedManifest) error {
	service := manifest.SOCKS5
	if !service.configured() {
		return errors.New("service manifest does not configure socks5")
	}
	rendered, err := loadRenderedSOCKS5(manifest.OutputDir)
	if err != nil {
		return err
	}
	if rendered.ConfigHash != service.ConfigHash || rendered.ManagedZone != manifest.ManagedZone || !reflect.DeepEqual(rendered.Endpoints, service.Endpoints) {
		return errors.New("socks5 runtime assignment or config changed; run render again")
	}
	for _, endpoint := range service.Endpoints {
		roles, ok := service.Networks[endpoint.Network]
		if !ok {
			return fmt.Errorf("socks5 endpoint %s has no rendered role addresses", endpoint.Network)
		}
		for _, target := range []struct {
			role    string
			address string
		}{
			{role: "socks", address: roles.SOCKS},
			{role: "http", address: roles.H2},
		} {
			if target.address == "" {
				continue
			}
			connection, err := net.DialTimeout("tcp", net.JoinHostPort(target.address, fmt.Sprint(endpoint.Port)), 3*time.Second)
			if err != nil {
				return fmt.Errorf("socks5 endpoint %s %s TCP readiness check failed: %w", endpoint.Network, target.role, err)
			}
			connection.Close()
		}
		if err := checkSOCKS5UDPDNS(net.JoinHostPort(roles.SOCKS, fmt.Sprint(endpoint.Port)), service.Resolver, 5*time.Second); err != nil {
			return fmt.Errorf("socks5 endpoint %s UDP DNS readiness check failed: %w", endpoint.Network, err)
		}
	}
	for _, endpoint := range service.Endpoints {
		roles := service.Networks[endpoint.Network]
		if len(service.AllowZones) > 0 {
			for _, acl := range []struct {
				name        string
				destination string
			}{
				{name: endpointACLName(endpoint.Network), destination: roles.SOCKS},
				{name: httpEndpointACLName(endpoint.Network), destination: roles.H2},
			} {
				if acl.destination == "" {
					continue
				}
				args := []string{"firewall", "endpoint", "apply", acl.name, "--destination", acl.destination, "--scope", "ip"}
				for _, selector := range service.AllowZones {
					args = append(args, "--allow-zone", selector)
				}
				if err := runPhoton(photonBinary, args...); err != nil {
					return fmt.Errorf("apply endpoint ACL before publish: %w", err)
				}
			}
		} else {
			acls := []string{endpointACLName(endpoint.Network)}
			if roles.H2 != "" {
				acls = append(acls, httpEndpointACLName(endpoint.Network))
			}
			for _, aclName := range acls {
				if err := runPhoton(photonBinary, "firewall", "endpoint", "remove", aclName); err != nil {
					return fmt.Errorf("remove stale endpoint ACL before unrestricted publish: %w", err)
				}
			}
		}
		if serviceControlsRoute(endpoint) {
			if err := runPhoton(photonBinary, "route", "announce", manifest.ManagedZone, endpoint.Assignment); err != nil {
				return fmt.Errorf("announce endpoint network %s: %w", endpoint.Network, err)
			}
		}
	}
	args := []string{"service", "publish"}
	for _, endpoint := range service.Endpoints {
		args = append(args, "--endpoint", fmt.Sprintf("%s,%s,%d", endpoint.Region, endpoint.Address, endpoint.Port))
	}
	if err := runPhoton(photonBinary, args...); err != nil {
		return err
	}
	previous, _ := loadPublishedSOCKS5(manifest.OutputDir)
	current := renderedSOCKS5Lock{resolvedSOCKS5: service, ManagedZone: manifest.ManagedZone}
	for _, old := range previous.Endpoints {
		sameName := false
		for _, endpoint := range service.Endpoints {
			if endpoint.Network == old.Network {
				sameName = true
				break
			}
		}
		if previous.Networks[old.Network].H2 != "" && (!sameName || service.Networks[old.Network].H2 == "") {
			if err := runPhoton(photonBinary, "firewall", "endpoint", "remove", httpEndpointACLName(old.Network)); err != nil {
				return err
			}
		}
		if endpointStillPublished(old, service.Endpoints) {
			continue
		}
		if serviceControlsRoute(old) && !manifestUsesSharedRoute(manifest, old.Assignment) {
			if err := runPhoton(photonBinary, "route", "withdraw", previous.ManagedZone, old.Assignment); err != nil {
				return err
			}
		}
		if !sameName {
			if err := runPhoton(photonBinary, "firewall", "endpoint", "remove", endpointACLName(old.Network)); err != nil {
				return err
			}
		}
	}
	return writeSOCKS5Lock(filepath.Join(manifest.OutputDir, "socks5", "published.json"), current)
}

type renderedSOCKS5Lock struct {
	resolvedSOCKS5
	ManagedZone string `json:"managed_zone"`
}

func loadRenderedSOCKS5(outputDir string) (renderedSOCKS5Lock, error) {
	path := filepath.Join(outputDir, "socks5", "resolved.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return renderedSOCKS5Lock{}, fmt.Errorf("read rendered state %s: %w; run render first", path, err)
	}
	var lock renderedSOCKS5Lock
	if err := json.Unmarshal(data, &lock); err != nil {
		return renderedSOCKS5Lock{}, fmt.Errorf("decode rendered state: %w", err)
	}
	return lock, nil
}

func loadPublishedSOCKS5(outputDir string) (renderedSOCKS5Lock, error) {
	path := filepath.Join(outputDir, "socks5", "published.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return loadRenderedSOCKS5(outputDir)
	}
	if err != nil {
		return renderedSOCKS5Lock{}, err
	}
	var lock renderedSOCKS5Lock
	if err := json.Unmarshal(data, &lock); err != nil {
		return renderedSOCKS5Lock{}, fmt.Errorf("decode published state: %w", err)
	}
	return lock, nil
}

func writeSOCKS5Lock(path string, lock renderedSOCKS5Lock) error {
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0o644)
}

func endpointStillPublished(old resolvedEndpoint, current []resolvedEndpoint) bool {
	for _, endpoint := range current {
		if endpoint.Network == old.Network && endpoint.Assignment == old.Assignment && endpoint.Address == old.Address {
			return true
		}
	}
	return false
}

func serviceControlsRoute(endpoint resolvedEndpoint) bool { return endpoint.Shared }

func endpointACLName(network string) string { return socks5ServiceName + "-" + network }

func httpEndpointACLName(network string) string { return "h2-" + network }

func runPhoton(binary string, args ...string) error {
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("photon %v: %w", args, err)
	}
	return nil
}

func writeJSON(file *os.File, value any) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
