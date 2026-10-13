package photonwindows

type fixturePacketTimingDirection uint8

const (
	fixturePacketTimingOutbound fixturePacketTimingDirection = iota
	fixturePacketTimingInbound
)

type fixturePacketTimingClass uint8

const (
	fixturePacketTimingUnknown fixturePacketTimingClass = iota
	fixturePacketTimingBusiness
	fixturePacketTimingControl
)

type fixturePacketTimingOutcome uint8

const (
	fixturePacketTimingDelivered fixturePacketTimingOutcome = iota
	fixturePacketTimingRejected
	fixturePacketTimingCryptoError
	fixturePacketTimingDeliveryError
	fixturePacketTimingQueueRejected
	fixturePacketTimingCanceled
)
