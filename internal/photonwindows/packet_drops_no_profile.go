//go:build !photon_profile

package photonwindows

// Ordinary builds inline these empty hooks and retain no diagnostic counters.
func recordRawIngressDrop()  {}
func recordLeafIngressDrop() {}
func recordESPIngressDrop()  {}
