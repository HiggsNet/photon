package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrackerLateBeyondOldRingAndDuplicates(t *testing.T) {
	tr := newTracker(64, 20000, time.Second)
	for i := 1; i <= 12000; i++ {
		if !tr.canSend() {
			t.Fatal("slot stuck")
		}
		tr.sent(time.Duration(i) * time.Second)
		tr.expire(time.Duration(i+1) * time.Second)
	}
	tr.receive(reply{seq: 1, at: 12002 * time.Second})
	tr.receive(reply{seq: 1, at: 12002 * time.Second})
	tr.receive(reply{seq: 9000, at: 12002 * time.Second})
	if tr.r.Sent != 12000 || tr.r.Expired != 12000 || tr.r.LateEchoed != 2 || tr.r.Echoed != 2 || tr.r.Duplicates != 1 {
		t.Fatalf("tracking lost valid old reply: %+v", tr.r)
	}
}

func TestTrackerReorderDeadlineAndSlotReuse(t *testing.T) {
	tr := newTracker(2, 100, time.Second)
	tr.sent(0)
	tr.sent(time.Millisecond)
	tr.receive(reply{seq: 2, at: 2 * time.Millisecond})
	if tr.canSend() {
		t.Fatal("reusing a pending sequence slot")
	}
	tr.receive(reply{seq: 1, at: 3 * time.Millisecond})
	if !tr.canSend() {
		t.Fatal("acknowledged slot remains blocked")
	}
	tr.sent(5 * time.Millisecond)
	tr.receive(reply{seq: 3, at: time.Second + 5*time.Millisecond})
	tr.receive(reply{seq: 4, at: time.Second})
	if tr.r.OnTime != 2 || tr.r.Expired != 1 || tr.r.LateEchoed != 1 || tr.r.Unsent != 1 || tr.r.Sent != tr.r.OnTime+tr.r.Expired {
		t.Fatalf("deadline accounting: %+v", tr.r)
	}
}

func TestPayloadEveryByteAndSequence(t *testing.T) {
	p := makePayload(1200, 3)
	binary.LittleEndian.PutUint64(p[16:24], 123456)
	if seq, kind := validatePayload(p, p); seq != 123456 || kind != 0 {
		t.Fatal(seq, kind)
	}
	for i := 0; i < len(p); i++ {
		if i >= 16 && i < 24 {
			continue
		}
		bad := append([]byte(nil), p...)
		bad[i] ^= 1
		_, kind := validatePayload(bad, p)
		if kind == 0 {
			t.Fatalf("unchecked byte %d", i)
		}
	}
	if _, kind := validatePayload(p[:1000], p); kind != 1 {
		t.Fatal("short accepted")
	}
}

func TestOutputExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := writeExclusive(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(path, []byte("second")); err == nil {
		t.Fatal("overwrote evidence")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "first" {
		t.Fatal("changed existing evidence", err)
	}
}

func TestLoopbackClientBoundedEcho(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, peer, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			c.WriteToUDP(buf[:n], peer)
		}
	}()
	o := options{mode: "client", local: "127.0.0.1", remote: "127.0.0.1", port: c.LocalAddr().(*net.UDPAddr).Port, flows: 1, window: 8, payload: 1200, seconds: 1, deadlineMS: 100, maxPackets: 1000000}
	r, err := runClient(o)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Completed || r.Totals.Sent < 100 || r.Totals.Corrupt != 0 || r.Totals.Expired != 0 || r.Totals.Echoed != r.Totals.Sent {
		t.Fatalf("loopback result: %+v", r)
	}
	c.Close()
	<-done
}

func TestLoopbackFaultAccounting(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan struct{})
	delayed := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, peer, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			switch binary.LittleEndian.Uint64(buf[16:24]) {
			case 1:
				copy := append([]byte(nil), buf[:n]...)
				go func() { defer close(delayed); time.Sleep(110 * time.Millisecond); c.WriteToUDP(copy, peer) }()
			case 2:
				continue
			case 3:
				c.WriteToUDP(buf[:n], peer)
				c.WriteToUDP(buf[:n], peer)
			default:
				c.WriteToUDP(buf[:n], peer)
			}
		}
	}()
	o := options{mode: "client", local: "127.0.0.1", remote: "127.0.0.1", port: c.LocalAddr().(*net.UDPAddr).Port, flows: 1, window: 64, payload: 1200, seconds: 1, deadlineMS: 50, maxPackets: 1000000}
	r, err := runClient(o)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Completed || r.Totals.Corrupt != 0 || r.Totals.Expired < 2 || r.Totals.Duplicates < 1 || r.Totals.LateEchoed < 1 || r.Totals.Sent != r.Totals.OnTime+r.Totals.Expired || r.Totals.Echoed != r.Totals.OnTime+r.Totals.LateEchoed {
		t.Fatalf("fault result: %+v", r)
	}
	c.Close()
	<-done
	<-delayed
}
