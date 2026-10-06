package photonwindows

import (
	"context"
	"net/netip"
)

// ownedPacketDevice is one configured, exclusively owned OS packet adapter.
// Close first rejects packets, removes owned routes/addresses, then releases it.
type ownedPacketDevice interface {
	Read(context.Context) ([]byte, error)
	Write([]byte) error
	Close() error
}

type packetDeviceFactory func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error)
