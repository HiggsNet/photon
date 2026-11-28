package photonproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"

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
}

type EmbeddedConfig struct {
	config v2Config
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
