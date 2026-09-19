package ipsec

import (
	"fmt"
	"time"
)

const (
	DefaultIKEPort  = 500
	DefaultNATTPort = 4500
)

type PortPlanOptions struct {
	Mode          string
	Range         *PortRange
	FixedIKE      uint16
	FixedNATT     uint16
	ObservedIKE   uint16
	ObservedNATT  uint16
	Generation    uint64
	Previous      *PortRecord
	PreviousGrace time.Duration
	PreviousLimit int
	Now           time.Time
}

// PlanPortPublication reuses an unchanged published record or plans its next
// automatic port generation. It does not mutate previous or persist the result.
// Explicit/manual rotation uses PlanPortRecord with a caller-selected generation.
func PlanPortPublication(mode string, portRange *PortRange, rotateInterval, previousGrace time.Duration, previous *PortRecord, now time.Time) (*PortRecord, error) {
	if mode == "" {
		mode = PortModeFixed
	}
	generation := uint64(1)
	if mode == PortModeRange && previous != nil && previous.Current != nil {
		generation = previous.Current.Generation
		if rotateInterval > 0 && (previous.UpdatedAt == 0 || now.After(time.Unix(previous.UpdatedAt, 0).Add(rotateInterval))) {
			generation++
		}
	}
	if previous != nil && previous.Current != nil && previous.Current.Generation == generation {
		previousMode := previous.Mode
		if previousMode == "" {
			previousMode = PortModeFixed
		}
		sameRange := previous.Range == nil && portRange == nil ||
			previous.Range != nil && portRange != nil && *previous.Range == *portRange
		if previousMode == mode && (mode != PortModeRange || sameRange) {
			return previous, nil
		}
	}
	return PlanPortRecord(PortPlanOptions{
		Mode: mode, Range: portRange, Generation: generation,
		Previous: previous, PreviousGrace: previousGrace, Now: now,
	})
}

func PlanPortRecord(opts PortPlanOptions) (*PortRecord, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	mode := opts.Mode
	if mode == "" {
		mode = PortModeFixed
	}
	selection, err := plannedCurrentPortSelection(opts)
	if err != nil {
		return nil, err
	}
	record := &PortRecord{
		Version:   1,
		Mode:      mode,
		Current:   &selection,
		UpdatedAt: now.Unix(),
	}
	if mode == PortModeRange {
		r := *opts.Range
		record.Range = &r
	}
	record.Previous = plannedPreviousPortSelections(opts, selection, now)
	if err := record.Validate(); err != nil {
		return nil, err
	}
	return record, nil
}

func plannedCurrentPortSelection(opts PortPlanOptions) (PortSelection, error) {
	switch opts.Mode {
	case "", PortModeFixed:
		localIKE := opts.FixedIKE
		if localIKE == 0 {
			localIKE = DefaultIKEPort
		}
		localNATT := opts.FixedNATT
		if localNATT == 0 {
			localNATT = DefaultNATTPort
		}
		return newPlannedPortSelection(opts.Generation, localIKE, localNATT, localIKE, localNATT, opts.ObservedIKE, opts.ObservedNATT), nil
	case PortModeRange:
		if opts.Range == nil {
			return PortSelection{}, fmt.Errorf("range mode requires range")
		}
		advertisedIKE, advertisedNATT, err := SelectPortsFromRange(*opts.Range, opts.Generation)
		if err != nil {
			return PortSelection{}, err
		}
		localIKE := opts.FixedIKE
		if localIKE == 0 {
			localIKE = DefaultIKEPort
		}
		localNATT := opts.FixedNATT
		if localNATT == 0 {
			localNATT = DefaultNATTPort
		}
		return newPlannedPortSelection(opts.Generation, localIKE, localNATT, advertisedIKE, advertisedNATT, opts.ObservedIKE, opts.ObservedNATT), nil
	default:
		return PortSelection{}, fmt.Errorf("unsupported port mode %q", opts.Mode)
	}
}

func newPlannedPortSelection(generation uint64, localIKE, localNATT, advertisedIKE, advertisedNATT, observedIKE, observedNATT uint16) PortSelection {
	return PortSelection{
		Generation: generation,
		IKE: PortBinding{
			Local:      localIKE,
			Advertised: advertisedIKE,
			Observed:   observedIKE,
		},
		NATT: PortBinding{
			Local:      localNATT,
			Advertised: advertisedNATT,
			Observed:   observedNATT,
		},
	}
}

func SelectPortsFromRange(r PortRange, generation uint64) (uint16, uint16, error) {
	if r.From == 0 || r.To == 0 || r.From > r.To {
		return 0, 0, fmt.Errorf("invalid port range %d-%d", r.From, r.To)
	}
	width := uint32(r.To) - uint32(r.From) + 1
	if width < 4 {
		return 0, 0, fmt.Errorf("port range %d-%d must contain at least two IKE/NAT-T port pairs", r.From, r.To)
	}
	// A generation owns a non-overlapping pair of advertised entry ports.
	// Advancing by one port would make the previous generation's NAT-T port
	// equal the current generation's IKE port while both are kept for grace.
	pairCount := width / 2
	generationIndex := generation
	if generationIndex > 0 {
		generationIndex--
	}
	pairIndex := uint32(generationIndex % uint64(pairCount))
	ike := uint16(uint32(r.From) + pairIndex*2)
	natt := ike + 1
	return ike, natt, nil
}

func plannedPreviousPortSelections(opts PortPlanOptions, current PortSelection, now time.Time) []PortSelection {
	if opts.Previous == nil || opts.PreviousGrace <= 0 {
		return nil
	}
	limit := opts.PreviousLimit
	if limit <= 0 {
		limit = 1
	}
	expires := now.Add(opts.PreviousGrace).Unix()
	var out []PortSelection
	if opts.Previous.Current != nil && opts.Previous.Current.Generation != current.Generation {
		previous := *opts.Previous.Current
		previous.ValidUntil = expires
		out = append(out, previous)
	}
	for _, previous := range opts.Previous.Previous {
		if len(out) >= limit {
			break
		}
		if previous.Generation == current.Generation || portSelectionExpired(previous, now) {
			continue
		}
		out = append(out, previous)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
