//go:build !photon_profile

package photonwindows

// Keep this zero-sized field first in queue/completion structs: a trailing
// zero-sized field can increase the containing struct's size.
type fixturePacketTiming struct{}

func beginFixturePacketTimingQueue(fixturePacketTimingDirection) fixturePacketTiming {
	return fixturePacketTiming{}
}
func (*fixturePacketTiming) QueueRejected()                    {}
func (*fixturePacketTiming) Dequeue()                          {}
func (fixturePacketTiming) Sampled() bool                      { return false }
func (*fixturePacketTiming) Classify(fixturePacketTimingClass) {}
func (*fixturePacketTiming) MarkAESBegin()                     {}
func (*fixturePacketTiming) MarkAESEnd()                       {}
func (*fixturePacketTiming) MarkDeliveryBegin()                {}
func (*fixturePacketTiming) MarkDeliveryEnd()                  {}
func (*fixturePacketTiming) Finish(fixturePacketTimingOutcome) {}
