package crypto

import "golang.org/x/crypto/blake2b"

func Hash(parts ...[]byte) []byte {
	if len(parts) == 1 {
		// One-shot hashing avoids allocating a streaming digest for key IDs
		// and authority payloads; the returned bytes remain caller-owned.
		sum := blake2b.Sum256(parts[0])
		return sum[:]
	}
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func KeyID(pub []byte) []byte {
	return Hash(pub)
}
