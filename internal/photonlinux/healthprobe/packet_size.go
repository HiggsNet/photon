package healthprobe

import "fmt"

// icmpPacketSize converts the configured inner IP packet size to ICMP bytes.
// The zero value keeps the existing raw/exec small probe behavior.
func icmpPacketSize(target ProbeTarget, cfg ProbeConfig) (int, error) {
	if cfg.PacketSize == 0 {
		return 8, nil
	}
	if cfg.PacketSize < 68 || cfg.PacketSize > 1400 {
		return 0, fmt.Errorf("ICMP inner packet size must be between 68 and 1400 bytes")
	}
	header := 20
	if target.PeerTunnelAddr.Is6() {
		header = 40
	}
	return cfg.PacketSize - header, nil
}
