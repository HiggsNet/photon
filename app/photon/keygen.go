package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

func keygen(path string) error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	key := privateKeyFile{
		Type:       "photon.ed25519.private.v1",
		PublicKey:  pub,
		PrivateKey: priv,
	}
	if err := writeJSONFile(path, 0o600, &key); err != nil {
		return err
	}
	fmt.Printf("wrote key: %s\n", path)
	fmt.Printf("public key: %s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}
