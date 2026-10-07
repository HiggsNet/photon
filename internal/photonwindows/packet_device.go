package photonwindows

import (
	"context"
	"errors"
	"net/netip"
)

// A conflicting foreign OS resource cannot be repaired by retrying or adopting
// it. Only a completion still matching current authorization may be fatal.
var errPacketDeviceConflict = errors.New("packet device conflicts with a foreign OS resource")

// ownedPacketDevice is one configured, exclusively owned OS packet adapter.
// Close first rejects packets, removes owned routes/addresses, then releases it.
type ownedPacketDevice interface {
	Read(context.Context) ([]byte, error)
	Write([]byte) error
	Close() error
}

type packetDeviceFactory func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error)
