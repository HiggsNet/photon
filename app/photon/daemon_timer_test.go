package main

import (
	"testing"
	"time"

	corehost "github.com/HiggsNet/photon/pkg/core/host"
)

func TestScheduleDaemonTimerUsesDaemonQueue(t *testing.T) {
	events := make(chan corehost.Event, 1)
	scheduler := corehost.NewScheduler(corehost.NewClock(nil), events)
	defer scheduler.Stop()
	d := &Daemon{daemonTimers: scheduler, daemonTimerEvents: events}
	if err := d.scheduleDaemonTimer(daemonTimerRouting, time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		fired, ok := event.(corehost.TimerFired)
		if !ok || fired.ID.Namespace != daemonRuntimeNamespace || fired.ID.Owner != daemonTimerOwner || fired.ID.Key != daemonTimerRouting {
			t.Fatalf("timer event = %#v", event)
		}
		if !scheduler.Accept(fired) {
			t.Fatal("daemon timer was not accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("daemon timer did not fire")
	}
}

func TestScheduleDaemonTimerCancelsDisabledFirewallInterval(t *testing.T) {
	events := make(chan corehost.Event, 1)
	scheduler := corehost.NewScheduler(corehost.NewClock(nil), events)
	defer scheduler.Stop()
	d := &Daemon{daemonTimers: scheduler, daemonTimerEvents: events}
	id := corehost.TimerID{Namespace: daemonRuntimeNamespace, Owner: daemonTimerOwner, Key: daemonTimerFirewall}
	if err := d.scheduleDaemonTimer(daemonTimerFirewall, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := d.scheduleDaemonTimer(daemonTimerFirewall, d.nextReconcileTime(daemonTimerFirewall, time.Now(), 0)); err != nil {
		t.Fatal(err)
	}
	if scheduler.Accept(corehost.TimerFired{ID: id, Generation: 1}) {
		t.Fatal("cancelled firewall timer generation was accepted")
	}
}

func TestPeriodicReconcilePhases(t *testing.T) {
	epoch := time.Unix(4200, 0)
	d := &Daemon{reconcileEpoch: epoch}
	cases := []struct {
		key      string
		interval time.Duration
		first    time.Duration
	}{
		{daemonTimerIPsec, defaultIPsecReconcileInterval, 15 * time.Second},
		{daemonTimerRouting, defaultRoutingReconcileInterval, 10 * time.Second},
		{daemonTimerFirewall, defaultFirewallReconcileInterval, 20 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if next := d.nextReconcileTime(tc.key, epoch, 0); !next.IsZero() {
				t.Fatalf("disabled deadline = %s, want zero", next)
			}
			// Startup, simultaneous state-driven flushes, and a stalled loop
			// must retain the phase without catching up missed slots.
			for _, offset := range []time.Duration{0, 5 * time.Second, tc.first, 60 * time.Second, 123 * time.Second} {
				now := epoch.Add(offset)
				next := d.nextReconcileTime(tc.key, now, tc.interval)
				if delay := next.Sub(now); delay <= 0 || delay > tc.interval {
					t.Fatalf("at %s delay = %s, want (0, %s]", offset, delay, tc.interval)
				}
				if remainder := next.Sub(epoch) % tc.interval; remainder != tc.first {
					t.Fatalf("at %s phase = %s, want %s", offset, remainder, tc.first)
				}
			}
		})
	}
}

func TestPeriodicReconcileIntervalChange(t *testing.T) {
	epoch := time.Unix(4200, 0)
	d := &Daemon{reconcileEpoch: epoch}
	// A custom short IPsec interval uses its own phase and stays bounded
	// after interval changes, even if the clock moves back before startup.
	for _, offset := range []time.Duration{-time.Second, 0, time.Second, 7 * time.Second} {
		now := epoch.Add(offset)
		next := d.nextReconcileTime(daemonTimerIPsec, now, 4*time.Second)
		if delay := next.Sub(now); delay <= 0 || delay > 4*time.Second {
			t.Fatalf("at %s delay = %s, want (0, 4s]", offset, delay)
		}
		if next.Unix()%4 != 1 {
			t.Fatalf("at %s next = %s, want phase 1s", offset, next)
		}
	}
}
