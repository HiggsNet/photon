//go:build !windows

package photonwindows

import (
	"context"
	"errors"
	"net/netip"
)

func openConfiguredPacketDevice(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
	return nil, errors.New("configured Wintun packet device requires Windows")
}
