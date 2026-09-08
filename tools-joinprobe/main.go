package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type probeBundle struct {
	Zone          zone.ZonePath      `json:"zone"`
	RootPublicKey string             `json:"root_public_key"`
	Network       *zone.NetworkState `json:"network"`
}

func main() {
	raw, err := func() ([]byte, error) {
		cleaned := strings.Map(func(r rune) rune {
			if r == 10 || r == 13 || r == 32 {
				return -1
			}
			return r
		}, readFile(os.Args[1]))
		if decoded, err := base64.StdEncoding.DecodeString(cleaned); err == nil {
			return decoded, nil
		}
		return base64.RawStdEncoding.DecodeString(cleaned)
	}()
	if err != nil {
		panic(err)
	}
	var b probeBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		panic(err)
	}
	fmt.Println("zone:", b.Zone)
	zs := b.Network.Zones[b.Zone]
	fmt.Println("target authority caps:", zs.Authority.Keys[0].Capabilities)
	parent := b.Network.Zones[b.Zone.Parent()]
	fmt.Println("parent delegations:", len(parent.Delegations), "revocations:", len(parent.Revocations))
	if parent.Authority != nil {
		fmt.Println("parent authority caps:", parent.Authority.Keys[0].Capabilities)
		fmt.Println("parent authority key:", base64.StdEncoding.EncodeToString(parent.Authority.Keys[0].Key))
	}
	for d := range parent.Delegations {
		fmt.Println("  delegation:", d)
	}
	for r := range parent.Revocations {
		fmt.Println("  revocation:", r)
	}
	for _, proof := range zs.ParentProof {
		fmt.Printf("parent proof: zone=%s signed_by=%s\n", proof.ZoneName, formatPub(proof.SignedBy))
	}
	for _, proof := range zs.ParentProof {
		fmt.Println("VerifyDelegation(proof):", photoncrypto.VerifyDelegation(proof, parent.Authority, b.Zone.Parent(), time.Now()))
	}
	probeZone := b.Zone.Parent()
	probeState := b.Network.Zones[probeZone]
	if probeState != nil && probeState.Authority != nil {
		for _, proof := range probeState.ParentProof {
			root := b.Network.Zones[zone.RootZone]
			fmt.Println("slapaper proof VerifyDelegation:", photoncrypto.VerifyDelegation(proof, root.Authority, zone.RootZone, time.Now()))
			fmt.Println("slapaper proof signed_by:", base64.StdEncoding.EncodeToString(proof.SignedBy))
			fmt.Println("root authority key:   ", base64.StdEncoding.EncodeToString(root.Authority.Keys[0].Key))
			fmt.Println("root authority caps:", root.Authority.Keys[0].Capabilities)
		}
	}
	fmt.Println("verify chain slapaper:", photoncrypto.VerifyChain(b.Network, b.Zone.Parent(), time.Now()))
	fmt.Println("verify full:", photoncrypto.VerifyChain(b.Network, b.Zone, time.Now()))
}

func readFile(p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func formatPub(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}
