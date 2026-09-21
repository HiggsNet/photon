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
	if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextReconcileTime(time.Now(), 0)); err != nil {
		t.Fatal(err)
	}
	if scheduler.Accept(corehost.TimerFired{ID: id, Generation: 1}) {
		t.Fatal("cancelled firewall timer generation was accepted")
	}
}

func TestNextReconcileTime(t *testing.T) {
	now := time.Unix(4200, 0)
	if next := nextReconcileTime(now, 0); !next.IsZero() {
		t.Fatalf("next disabled = %s, want zero", next)
	}
	if next := nextReconcileTime(now, 30*time.Second); !next.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("next = %s, want %s", next, now.Add(30*time.Second))
	}
}
