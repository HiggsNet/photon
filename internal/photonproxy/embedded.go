package photonproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
)

// Host implements the operations owned by the local Photon daemon. Direct
// sockets are tied to the supplied authenticated link, including its generation.
type Host struct {
	Read         func(context.Context, service.ProxyReadRequest) (service.ProxyReadResponse, error)
	Publish      func(context.Context, service.ProxyV2Publication) error
	DialDirect   func(context.Context, service.ProxyDirectLink, uint16) (net.Conn, error)
	ListenDirect func(context.Context, uint16) (net.Listener, error)
	DialPeer     func(context.Context, string, string, netip.AddrPort) (net.Conn, error)
	LookupPeer   func(context.Context, string, string) ([]netip.Addr, error)
	DialExit     func(context.Context, string, netip.AddrPort) (net.Conn, error)
	ClientReady  func(*EmbeddedClient)
}

type EmbeddedConfig struct {
	config v2Config
}

func NewDesktopClient(statePath string) *EmbeddedConfig {
	return &EmbeddedConfig{config: v2Config{
		StateDir: filepath.Clean(statePath) + ".proxy-v2", DirectoryRefresh: 2 * time.Second,
		Client: &v2ClientConfig{DefaultListen: "127.0.0.1:0"},
	}}
}

func LoadEmbeddedConfig(path string) (*EmbeddedConfig, error) {
	config, err := readNodeConfig(path, true)
	if err != nil {
		return nil, err
	}
	if config.Client != nil {
		if err := validateEmbeddedAdminAddress(config.Client.Admin.Socket); err != nil {
			return nil, err
		}
	}
	return &EmbeddedConfig{config: config}, nil
}

func (c *EmbeddedConfig) Run(ctx context.Context, host Host) error {
	if host.Read == nil || host.Publish == nil || host.DialDirect == nil || host.ListenDirect == nil {
		return errors.New("embedded proxy requires a directory, publisher and direct transport")
	}
	return runV2Node(ctx, c.config, host)
}

func (c *EmbeddedConfig) Rotate(group string, key bool) error {
	return rotateV2Config(c.config, group, key)
}

type EmbeddedRoute struct {
	Name        string   `json:"name"`
	Address     string   `json:"address"`
	Port        uint16   `json:"port"`
	Hops        []string `json:"hops"`
	UDPPrefixes []string `json:"udp_prefixes,omitempty"`
}

type EmbeddedClientRequest struct {
	Action      string   `json:"action"`
	Name        string   `json:"name,omitempty"`
	Hops        []string `json:"hops,omitempty"`
	UDPPrefixes []string `json:"udp_prefixes,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Target      string   `json:"target,omitempty"`
}

type EmbeddedClient struct {
	node    *v2Node
	manager *routeManager
	mu      sync.Mutex
	probe   *embeddedProbe
}

type embeddedProbe struct {
	Name   string         `json:"name"`
	Result *v2ProbeResult `json:"result,omitempty"`
	cancel context.CancelFunc
}

func (c *EmbeddedClient) Routes() []EmbeddedRoute {
	routes := []EmbeddedRoute{}
	if c == nil || c.node.ctx.Err() != nil {
		return routes
	}
	for _, item := range c.manager.list() {
		address, err := netip.ParseAddrPort(item.Listen)
		if err == nil && address.Addr().IsLoopback() && address.Port() != 0 {
			routes = append(routes, EmbeddedRoute{item.Name, address.Addr().String(), address.Port(), item.Hops, item.UDPPrefixes})
		}
	}
	return routes
}

func (c *EmbeddedClient) Request(request EmbeddedClientRequest) (any, error) {
	if c == nil || c.node.ctx.Err() != nil {
		return nil, errors.New("Photon Proxy v2 client is starting or disabled")
	}
	if request.Action != "list" {
		if name := request.Name; len(name) > 128 || strings.TrimSpace(name) != name || name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return nil, errors.New("invalid proxy route name")
		}
	}
	route := clientRoute{Hops: request.Hops, UDPPrefixes: request.UDPPrefixes}
	if request.Action == "create" {
		route.Listen = "127.0.0.1:0"
		if _, err := c.manager.create(request.Name, route); err != nil {
			return nil, err
		}
	} else if request.Action != "list" {
		binding := c.manager.localBinding(request.Name)
		if binding == nil {
			return nil, errRouteNotFound
		}
		switch request.Action {
		case "update":
			// Pin the existing listener while validating and retaining its port.
			route.Listen = binding.listener.Addr().String()
			if _, err := c.manager.replace(request.Name, route); err != nil {
				return nil, err
			}
			c.clearProbe(request.Name)
		case "delete":
			if err := c.manager.removeBinding(request.Name, binding); err != nil {
				return nil, err
			}
			c.clearProbe(request.Name)
		case "probe":
			probe := v2ProbeRequest{Kind: request.Kind, Protocol: request.Protocol, Target: request.Target}
			limit, err := probe.timeout(true)
			if err != nil {
				return nil, err
			}
			if err := c.startProbe(request.Name, probe, limit, binding.client.Load().client); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown proxy action %q", request.Action)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return struct {
		Routes    []EmbeddedRoute     `json:"routes"`
		Directory v2EndpointDirectory `json:"directory"`
		Probe     *embeddedProbe      `json:"probe,omitempty"`
	}{c.Routes(), v2ListEndpoints(c.node.directory.snapshotV2(), time.Now()), c.probe}, nil
}

func (c *EmbeddedClient) startProbe(name string, request v2ProbeRequest, limit time.Duration, opener tunnelOpener) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.probe != nil && c.probe.Result == nil {
		return errors.New("a proxy route test is already running")
	}
	ctx, cancel := context.WithTimeout(c.node.ctx, limit)
	pending := &embeddedProbe{Name: name, cancel: cancel}
	c.probe = pending
	go func() {
		defer cancel()
		result := probeV2(ctx, opener, request)
		c.mu.Lock()
		// Replace the snapshot so an in-flight JSON encoder sees immutable data.
		if c.probe == pending {
			c.probe = &embeddedProbe{Name: name, Result: &result}
		}
		c.mu.Unlock()
	}()
	return nil
}

func (c *EmbeddedClient) clearProbe(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if probe := c.probe; probe != nil && probe.Name == name {
		if probe.cancel != nil {
			probe.cancel()
		}
		c.probe = nil
	}
}
