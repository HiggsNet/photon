package main

import (
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type ipsecContactObservation struct {
	Quality   ipsec.ContactPointQuality
	UpdatedAt time.Time
}

// The daemon loop records endpoint outcomes, not control readers. Keep this
// runtime evidence separate from signed records and from Gossip reachability.
func (d *Daemon) observeIPsecContactOutcomes(previous, current map[string]ipsec.LinkInstance, now time.Time) {
	if d.ipsecContactQuality == nil {
		d.ipsecContactQuality = map[zone.ZonePath]map[string]ipsecContactObservation{}
	}
	for peer, contacts := range d.ipsecContactQuality {
		for key, entry := range contacts {
			if now.Sub(entry.UpdatedAt) > 30*time.Minute && !now.Before(entry.Quality.BackoffUntil) {
				delete(contacts, key)
			}
		}
		if len(contacts) == 0 {
			delete(d.ipsecContactQuality, peer)
		}
	}
	for id, instance := range current {
		point := instance.SelectedContact
		if point.Address == "" || !ipsec.IsActiveInitiatorRole(instance.InitiatorRole) || instance.StagedGeneration != 0 || instance.RotatePhase != ipsec.RotatePhaseIdle {
			continue
		}
		old, existed := previous[id]
		var attemptError *ipsec.ContactAttemptError
		failed := instance.FailureCount > old.FailureCount && errors.As(instance.LastFailure, &attemptError)
		succeeded := instance.ActualState == ipsec.LinkStateUp && (!existed || old.ActualState != ipsec.LinkStateUp || old.SelectedContact.Key() != point.Key())
		if !failed && !succeeded {
			continue
		}
		contacts := d.ipsecContactQuality[instance.PeerZone]
		if contacts == nil {
			contacts = map[string]ipsecContactObservation{}
			d.ipsecContactQuality[instance.PeerZone] = contacts
		}
		entry := contacts[point.Key()]
		if failed {
			entry.Quality.Failures++
			// A contact must remain deferred through the next reconcile; otherwise
			// a one-second apply backoff expires before a one-minute timer sees it.
			hold := max(2*d.ipsecReconcileInterval(), time.Minute)
			entry.Quality.BackoffUntil = now.Add(hold)
			if applyBackoff := time.Unix(instance.BackoffUntil, 0); applyBackoff.After(entry.Quality.BackoffUntil) {
				entry.Quality.BackoffUntil = applyBackoff
			}
		} else {
			entry.Quality.Successes++
			entry.Quality.BackoffUntil = time.Time{}
		}
		entry.UpdatedAt = now
		contacts[point.Key()] = entry
	}
}
