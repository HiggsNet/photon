//go:build !windows && photon_profile

package photonwindows

import "time"

// Only the Windows QPC clock is used for native measurements. This monotonic
// fallback lets portable lifecycle and ownership tests exercise the same API.
type fixturePacketTimingClock struct {
	origin    time.Time
	frequency uint64
}

func newFixturePacketTimingClock() (fixturePacketTimingClock, error) {
	return fixturePacketTimingClock{origin: time.Now(), frequency: 1_000_000_000}, nil
}

func (*fixturePacketTimingClock) name() string { return "monotonic_test_fallback" }
func (c *fixturePacketTimingClock) read() (int64, bool) {
	return time.Since(c.origin).Nanoseconds(), true
}
