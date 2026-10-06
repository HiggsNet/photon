package crypto

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"testing"
)

func TestHashMatchesStreamingForAllInputShapes(t *testing.T) {
	for _, size := range []int{0, 1, 32, 127, 128, 129, 1024, 4096} {
		data := bytes.Repeat([]byte{0x6d}, size)
		for _, parts := range [][][]byte{{data}, {nil, data}, {data[:size/2], data[size/2:]}} {
			h, err := blake2b.New256(nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range parts {
				h.Write(part)
			}
			want := h.Sum(nil)
			got := Hash(parts...)
			if !bytes.Equal(got, want) {
				t.Fatalf("size=%d parts=%d: changed hash", size, len(parts))
			}
			got[0] ^= 0xff
			if !bytes.Equal(Hash(parts...), want) {
				t.Fatal("returned hash is shared")
			}
		}
	}
	h, _ := blake2b.New256(nil)
	if !bytes.Equal(Hash(), h.Sum(nil)) {
		t.Fatal("empty part list changed hash")
	}
}

func BenchmarkHashSinglePart(b *testing.B) {
	for _, size := range []int{32, 256} {
		data := bytes.Repeat([]byte{0x6d}, size)
		b.Run(fmt.Sprintf("%d/streaming", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h, _ := blake2b.New256(nil)
				h.Write(data)
				hashBenchmarkResult = h.Sum(nil)
			}
		})
		b.Run(fmt.Sprintf("%d/oneshot", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				hashBenchmarkResult = Hash(data)
			}
		})
	}
}

var hashBenchmarkResult []byte
