package photonproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
)

type v2TLSMaterial struct {
	Cert []byte `json:"cert"`
	Key  []byte `json:"key"`
}

type v2TLSState struct {
	Current    v2TLSMaterial  `json:"current"`
	Next       *v2TLSMaterial `json:"next,omitempty"`
	Retired    *v2TLSMaterial `json:"retired,omitempty"`
	ActivateAt time.Time      `json:"activate_at,omitzero"`
	RetireAt   time.Time      `json:"retire_at,omitzero"`
}

func makeV2TLS(now time.Time, lifetime time.Duration, reuse []byte) (v2TLSMaterial, error) {
	var material v2TLSMaterial
	var key ed25519.PrivateKey
	if len(reuse) != 0 {
		block, _ := pem.Decode(reuse)
		if block == nil {
			return material, errors.New("missing stored TLS private key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return material, err
		}
		var ok bool
		key, ok = parsed.(ed25519.PrivateKey)
		if !ok {
			return material, errors.New("stored TLS key is not Ed25519")
		}
		material.Key = reuse
	} else {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return material, err
		}
		key = generated
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return material, err
		}
		material.Key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return material, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Photon Proxy"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return material, err
	}
	material.Cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return material, nil
}

func (m v2TLSMaterial) certificate() (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(m.Cert, m.Key)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
	}
	return &cert, nil
}

func (s v2TLSState) pins() ([]string, error) {
	var pins []string
	for _, material := range []*v2TLSMaterial{&s.Current, s.Next, s.Retired} {
		if material == nil {
			continue
		}
		cert, err := material.certificate()
		if err != nil {
			return nil, err
		}
		pins = append(pins, service.ProxyPublicKeyID(cert.Leaf))
	}
	return pins, nil
}

func v2ServerTLS(active *atomic.Pointer[tls.Certificate]) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert := active.Load()
		if cert == nil {
			return nil, errors.New("proxy TLS certificate is unavailable")
		}
		return cert, nil
	}}
}
