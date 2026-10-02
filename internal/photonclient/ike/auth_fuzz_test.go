package ike

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func FuzzVerifyAuth(f *testing.F) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	octets := []byte("bounded IKE transcript fixture")
	f.Add([]byte(public), octets, signAuth(private, octets))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, key, signed, auth []byte) {
		keyBefore, signedBefore, authBefore := bytes.Clone(key), bytes.Clone(signed), bytes.Clone(auth)
		err := verifyAuth(ed25519.PublicKey(key), signed, auth)
		if !bytes.Equal(key, keyBefore) || !bytes.Equal(signed, signedBefore) || !bytes.Equal(auth, authBefore) {
			t.Fatal("AUTH verification mutated caller data")
		}
		if err == nil && (len(key) != ed25519.PublicKeySize || len(auth) != 76 || !ed25519.Verify(ed25519.PublicKey(key), signed, auth[12:])) {
			t.Fatal("accepted unauthenticated signature")
		}
	})
}
