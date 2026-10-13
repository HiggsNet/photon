package crypto

import "crypto/ed25519"

const (
	verifierMaxEntries = 512
	// Bounds retained key/payload bytes; Go map and object overhead is extra
	// and independently bounded by verifierMaxEntries.
	verifierMaxBytes   = 512 << 10
	verifierMaxPayload = 4 << 10
)

// Verifier belongs to one serialized caller. It remembers only successful
// Ed25519 mathematical checks, keyed by every public-key, domain-payload and
// signature byte. Authority, capabilities, hashes, revocation and exact-time
// checks still execute on every Verify call. It stores no authorization grant.
//
// The zero value enables this bounded memo. A nil receiver performs the same
// validation without memoization; the package-level functions use that path.
// Instances must not be shared between concurrent owners.
type Verifier struct {
	signatures map[signatureKey]struct{}
	bytes      int
}

type signatureKey struct {
	public    [ed25519.PublicKeySize]byte
	signature [ed25519.SignatureSize]byte
	payload   string
}

func (v *Verifier) verifySignature(public ed25519.PublicKey, payload, signature []byte) bool {
	if len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	if v == nil || len(payload) > verifierMaxPayload {
		return ed25519.Verify(public, payload, signature)
	}
	// Arrays and a safe string conversion detach all caller-owned buffers. No
	// hash-only shortcut or pointer identity can turn mutated bytes into a hit.
	key := signatureKey{public: [ed25519.PublicKeySize]byte(public), signature: [ed25519.SignatureSize]byte(signature), payload: string(payload)}
	if _, ok := v.signatures[key]; ok {
		return true
	}
	if !ed25519.Verify(public, payload, signature) {
		return false
	}
	size := len(public) + len(signature) + len(payload)
	if len(v.signatures) >= verifierMaxEntries || v.bytes+size > verifierMaxBytes {
		clear(v.signatures)
		v.bytes = 0
	}
	if v.signatures == nil {
		v.signatures = make(map[signatureKey]struct{})
	}
	v.signatures[key] = struct{}{}
	v.bytes += size
	return true
}
