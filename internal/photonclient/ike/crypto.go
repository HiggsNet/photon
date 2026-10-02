package ike

// This implementation follows RFC 7296 sections 2.13, 2.14 and 3.4, and RFC
// 4868. It is an independent implementation using Go's standard library.
import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// GenerateP256Key creates a fresh ephemeral DH group 19 key. The caller must
// supply a cryptographically secure source (normally crypto/rand.Reader).
func GenerateP256Key(random io.Reader) (*ecdh.PrivateKey, error) {
	if random == nil {
		return nil, errors.New("IKE: missing randomness source")
	}
	return ecdh.P256().GenerateKey(random)
}

// P256PublicKey returns the IKE group 19 wire encoding, without SEC1's 04 prefix.
func P256PublicKey(key *ecdh.PrivateKey) []byte {
	if key == nil || key.Curve() != ecdh.P256() {
		return nil
	}
	return append([]byte(nil), key.PublicKey().Bytes()[1:]...)
}

func P256SharedSecret(key *ecdh.PrivateKey, peer []byte) ([]byte, error) {
	if key == nil || key.Curve() != ecdh.P256() || len(peer) != 64 {
		return nil, errors.New("IKE: invalid group 19 key")
	}
	encoded := make([]byte, 65)
	encoded[0] = 4
	copy(encoded[1:], peer)
	public, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil, err
	}
	return key.ECDH(public)
}

func PRFSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// PRFPlusSHA256 implements RFC 7296's one-byte counter expansion. Its output
// is deliberately bounded to 255 blocks; a counter must never wrap.
func PRFPlusSHA256(key, seed []byte, size int) ([]byte, error) {
	if size < 0 || size > 255*sha256.Size || len(seed) > 65535 {
		return nil, errors.New("IKE: invalid PRF+ size")
	}
	out := make([]byte, 0, size)
	var previous []byte
	for counter := 1; len(out) < size; counter++ {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(seed)
		_, _ = mac.Write([]byte{byte(counter)})
		previous = mac.Sum(nil)
		count := min(size-len(out), len(previous))
		out = append(out, previous[:count]...)
	}
	return out, nil
}

type IKEKeys struct {
	SKD, SKAI, SKAR, SKEI, SKER, SKPI, SKPR []byte
}

// DeriveIKEKeys derives initial IKE SA keys for PRF-HMAC-SHA256,
// AUTH-HMAC-SHA256-128 and AES-CBC-128, with P-256 DH. Rekey uses a different
// SKEYSEED expression and must not call this initial-exchange function.
func DeriveIKEKeys(shared, initiatorNonce, responderNonce []byte, initiatorSPI, responderSPI uint64) (IKEKeys, error) {
	if len(shared) != 32 || len(initiatorNonce) < 16 || len(initiatorNonce) > 256 || len(responderNonce) < 16 || len(responderNonce) > 256 || initiatorSPI == 0 || responderSPI == 0 {
		return IKEKeys{}, errors.New("IKE: invalid initial key derivation input")
	}
	nonces := append(append([]byte(nil), initiatorNonce...), responderNonce...)
	skeyseed := PRFSHA256(nonces, shared)
	seed := append([]byte(nil), nonces...)
	seed = binary.BigEndian.AppendUint64(seed, initiatorSPI)
	seed = binary.BigEndian.AppendUint64(seed, responderSPI)
	material, err := PRFPlusSHA256(skeyseed, seed, 192)
	if err != nil {
		return IKEKeys{}, err
	}
	return IKEKeys{
		SKD: material[0:32:32], SKAI: material[32:64:64], SKAR: material[64:96:96],
		SKEI: material[96:112:112], SKER: material[112:128:128],
		SKPI: material[128:160:160], SKPR: material[160:192:192],
	}, nil
}
