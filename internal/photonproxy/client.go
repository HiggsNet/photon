package photonproxy

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type clientConfig struct {
	DirectorySocket string                 `yaml:"directory_socket"`
	ServerCA        string                 `yaml:"server_ca"`
	DelegationKey   string                 `yaml:"delegation_key"`
	PublicDevice    string                 `yaml:"public_device"`
	PhotonDevice    string                 `yaml:"photon_device"`
	Routes          map[string]clientRoute `yaml:"routes"`
	AdminSocket     string                 `yaml:"admin_socket"`
	RouteState      string                 `yaml:"route_state"`
}

type clientRoute struct {
	Listen      string   `yaml:"listen" json:"listen,omitempty"`
	Hops        []string `yaml:"hops" json:"hops"`
	UDPPrefixes []string `yaml:"udp_prefixes" json:"udp_prefixes,omitempty"`
}

type clientEntry struct {
	name    string
	listen  netip.AddrPort
	hops    chainPath
	udp     string
	v2Route string
}

func runClient(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("photon-proxy client", flag.ContinueOnError)
	path := flags.String("config", "", "YAML configuration with named SOCKS5 routes")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("client requires -config")
	}
	config, err := loadClientConfig(*path)
	if err != nil {
		return err
	}
	var state *routeState
	if config.RouteState != "" {
		state, config.Routes, err = openRouteState(config.RouteState, config.Routes)
		if err != nil {
			return err
		}
		defer state.Close()
	}
	entries, err := prepareClientEntries(config.Routes)
	if err != nil {
		return err
	}
	key, err := readDelegationPrivateKey(config.DelegationKey)
	if err != nil {
		return fmt.Errorf("delegation_key: %w", err)
	}
	pool, err := newChainPool(config.ServerCA, config.PublicDevice, config.PhotonDevice)
	if err != nil {
		return fmt.Errorf("server_ca: %w", err)
	}
	defer pool.closeIdleConnections()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	directory, err := openProxyDirectory(ctx, config.DirectorySocket)
	if err != nil {
		return fmt.Errorf("read proxy directory: %w", err)
	}

	var admin net.Listener
	if config.AdminSocket != "" {
		admin, err = listenClientAdmin(config.AdminSocket)
		if err != nil {
			return err
		}
		defer admin.Close()
	}
	manager := newRouteManager(ctx, state, func(entry clientEntry) *chainClient {
		return &chainClient{directory: directory, hops: entry.hops, key: key, udp: entry.udp, pool: pool}
	})
	defer manager.close()
	if err := manager.start(config.Routes, entries); err != nil {
		return err
	}
	if admin == nil {
		select {
		case <-ctx.Done():
			return nil
		case err := <-manager.errors:
			return err
		}
	}
	return serveClientAdmin(ctx, admin, manager)
}

func loadClientConfig(path string) (clientConfig, error) {
	var config clientConfig
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			err = errors.New("multiple YAML documents")
		}
		return config, fmt.Errorf("decode %s: %w", path, err)
	}
	if config.DirectorySocket == "" || config.ServerCA == "" || config.DelegationKey == "" {
		return config, errors.New("directory_socket, server_ca and delegation_key are required")
	}
	if (config.AdminSocket == "") != (config.RouteState == "") {
		return config, errors.New("admin_socket and route_state must be set together")
	}
	if config.AdminSocket == "" && len(config.Routes) == 0 {
		return config, errors.New("at least one SOCKS5 route is required")
	}
	for _, location := range []*string{&config.DirectorySocket, &config.ServerCA, &config.DelegationKey, &config.AdminSocket, &config.RouteState} {
		if *location != "" && !filepath.IsAbs(*location) {
			*location = filepath.Join(filepath.Dir(path), *location)
		}
	}
	return config, nil
}

func prepareClientEntries(routes map[string]clientRoute) ([]clientEntry, error) {
	entries := make([]clientEntry, 0, len(routes))
	listeners := make(map[netip.AddrPort]string, len(routes))
	for _, name := range slices.Sorted(maps.Keys(routes)) {
		entry, err := prepareClientEntry(name, routes[name], false)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", name, err)
		}
		if other, exists := listeners[entry.listen]; exists {
			return nil, fmt.Errorf("routes %q and %q use the same listen address %s", other, name, entry.listen)
		}
		listeners[entry.listen] = name
		entries = append(entries, entry)
	}
	return entries, nil
}

func prepareClientEntry(name string, route clientRoute, allowAutoPort bool) (clientEntry, error) {
	entry := clientEntry{name: name}
	if strings.TrimSpace(name) == "" || len(route.Hops) == 0 {
		return entry, errors.New("route needs a name and at least one hop")
	}
	address, err := netip.ParseAddrPort(route.Listen)
	if err != nil || (!allowAutoPort && address.Port() == 0) || !address.Addr().IsLoopback() || address.Addr().Zone() != "" {
		return entry, errors.New("listen must be a loopback IP and a valid TCP port")
	}
	entry.listen = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	for _, hop := range route.Hops {
		if err := entry.hops.add(hop); err != nil {
			return entry, err
		}
	}
	if len(route.UDPPrefixes) != 0 {
		entry.udp, err = normalizeUDPScope(strings.Join(route.UDPPrefixes, ","))
	}
	return entry, err
}
