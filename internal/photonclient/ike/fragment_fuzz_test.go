package ike

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

// Operations are triples: kind, fragment set, fragment index. Keep the corpus
// replay deterministic and bounded, including encryption IVs and the clock.
func FuzzSKFSequence(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 3, 0, 0, 2, 0, 0, 1, 0, 0, 0}) // reverse completion
	f.Add([]byte{0, 0, 0, 1, 2, 1, 0, 2, 1, 0, 0, 1}) // forged then real PMTU restart
	f.Add([]byte{0, 0, 0, 2, 0, 0, 3, 0, 0, 4, 0, 0, 0, 1, 1})
	f.Add([]byte{0, 0, 0, 5, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 1})
	var long []byte
	for n := 0; n < 256; n++ {
		long = append(long, byte(n%8), byte(n%3), byte(n))
	}
	f.Add(long)
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 3072 {
			return
		}
		plain := bytes.Repeat([]byte("SKF sequence payload"), 48)
		h := Header{InitiatorSPI: 1, ResponderSPI: 2, ExchangeType: ExchangeIKEAuth, Flags: FlagResponse, MessageID: 1}
		ek, ak := bytes.Repeat([]byte{3}, 16), bytes.Repeat([]byte{4}, 32)
		var sets, conflicts [3][][]byte
		for n, budget := range []int{340, 260, 84} {
			var err error
			sets[n], err = SealSKF(h, PayloadIDr, plain, ek, ak, budget, bytes.NewReader(make([]byte, 4096)))
			if err != nil {
				t.Fatal(err)
			}
			conflicts[n], err = SealSKF(h, PayloadIDr, bytes.Repeat([]byte{0xa5}, len(plain)), ek, ak, budget, bytes.NewReader(make([]byte, 4096)))
			if err != nil {
				t.Fatal(err)
			}
		}
		var r skfReassembly
		now := time.Unix(100, 0)
		started := now
		active := -1
		seen := map[int]bool{}
		resetModel := func() { active = -1; seen = map[int]bool{} }
		check := func() {
			t.Helper()
			count, size := 0, 0
			for _, p := range r.parts {
				if p != nil {
					count++
					size += len(p)
				}
			}
			if count != r.received || size != r.size || size > MaxMessageSize || count > maxFragments {
				t.Fatal("unbounded or inconsistent retained fragments")
			}
			if active < 0 {
				if !reflect.DeepEqual(r, skfReassembly{}) {
					t.Fatal("empty exchange retained state")
				}
			} else if r.total != len(sets[active]) || r.received != len(seen) || r.started != started {
				t.Fatal("cache differs from accepted fragment history")
			}
		}
		for offset := 0; offset+2 < len(ops); offset += 3 {
			kind, set := ops[offset]%8, int(ops[offset+1])%len(sets)
			index := int(ops[offset+2]) % len(sets[set])
			if kind == 3 { // Explicit cancellation must wipe borrowed plaintext.
				old := r.parts
				r.Reset()
				assertSKFWiped(t, old)
				resetModel()
				check()
				continue
			}
			if kind == 4 {
				now = now.Add(fragmentTimeout)
			} else if kind == 7 {
				now = now.Add(time.Second)
			}
			old := r.parts
			expired := active >= 0 && !now.Before(started.Add(fragmentTimeout))
			if expired {
				resetModel()
			}
			packet := bytes.Clone(sets[set][index])
			expected := h
			invalid := false
			switch kind {
			case 1: // Authenticated framing, invalid ICV (including PMTU claims).
				packet[len(packet)-1] ^= 1
				invalid = true
			case 2: // Conflicting authenticated duplicate, only if already retained.
				if active == set && seen[index] {
					packet = bytes.Clone(conflicts[set][index])
					invalid = true
				}
			case 5:
				expected.MessageID++
				invalid = true
			case 6: // Arbitrary truncation cannot become a complete authenticated SKF.
				packet = packet[:int(ops[offset+2])%len(packet)]
				invalid = true
			}
			before := cloneSKFState(r)
			packetBefore := bytes.Clone(packet)
			first, out, done, err := r.Add(packet, expected, ek, ak, now)
			if !bytes.Equal(packet, packetBefore) {
				t.Fatal("Add mutated caller ciphertext")
			}
			if expired {
				assertSKFWiped(t, old)
				before = skfReassembly{}
			}
			if invalid || active >= 0 && len(sets[set]) < len(sets[active]) {
				if err == nil || done || out != nil || first != 0 || !reflect.DeepEqual(before, r) {
					t.Fatal("rejected input advanced or poisoned reassembly")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if active < 0 || len(sets[set]) > len(sets[active]) {
					assertSKFWiped(t, old)
					resetModel()
					active, started = set, now
				}
				seen[index] = true
				wantDone := len(seen) == len(sets[active])
				if done != wantDone {
					t.Fatal("completion without exactly one full accepted set")
				}
				if done {
					if first != PayloadIDr || !bytes.Equal(out, plain) {
						t.Fatal("completed plaintext differs from authenticated message")
					}
					assertSKFWiped(t, old)
					resetModel()
				} else if out != nil || first != 0 {
					t.Fatal("incomplete exchange exposed plaintext")
				}
			}
			check()
		}
		old := r.parts
		r.Reset()
		assertSKFWiped(t, old)
		// Regardless of preceding failures/restarts, a fresh cycle must work.
		for index := len(sets[2]) - 1; index >= 0; index-- {
			_, out, done, err := r.Add(sets[2][index], h, ek, ak, now)
			if err != nil || done != (index == 0) || done && !bytes.Equal(out, plain) {
				t.Fatal("failed to recover after reset", err)
			}
		}
	})
}

func cloneSKFState(r skfReassembly) skfReassembly {
	for n, part := range r.parts {
		r.parts[n] = bytes.Clone(part)
	}
	return r
}

func assertSKFWiped(t *testing.T, parts [maxFragments][]byte) {
	t.Helper()
	for _, part := range parts {
		for _, b := range part {
			if b != 0 {
				t.Fatal("retired plaintext was not wiped")
			}
		}
	}
}
