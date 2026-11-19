package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
)

func runPublication(ctx context.Context, command string, args []string) error {
	flags := flag.NewFlagSet("photon-proxy "+command, flag.ContinueOnError)
	control := os.Getenv("PHOTON_CONTROL_SOCKET")
	if control == "" {
		control = "/run/photon/photon.sock"
	}
	socket := flags.String("control-socket", control, "local Photon administrative socket")
	version := flags.Uint64("expect-version", 0, "require this current record version (0 means absent)")
	var cert, endpoint string
	var ttl time.Duration
	var announcePort uint
	var relay bool
	var delegationPublicKey string
	if command == "publish" {
		flags.StringVar(&cert, "tls-cert", "", "PEM proxy certificate (public part)")
		flags.StringVar(&endpoint, "endpoint", "", "reachable TCP host:port (omit for a client-only node)")
		flags.UintVar(&announcePort, "announce-port", 0, "TCP port to publish with the single manual IPsec announce host")
		flags.BoolVar(&relay, "relay", false, "publish the endpoint as a relay instead of an exit")
		flags.StringVar(&delegationPublicKey, "delegation-pubkey", "", "PEM Ed25519 public key for signed delegation")
		flags.DurationVar(&ttl, "ttl", 24*time.Hour, "capability lifetime")
	}
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	var mutation service.ProxyMutation
	var reuseAnnounceHost bool
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "expect-version" {
			mutation.ExpectedVersion = version
		}
		if f.Name == "announce-port" {
			reuseAnnounceHost = true
		}
	})
	if command == "publish" {
		if reuseAnnounceHost && (announcePort == 0 || announcePort > 65535 || endpoint != "") {
			return errors.New("use either -endpoint or a valid -announce-port")
		}
		record, err := publication(cert, endpoint, ttl, time.Now())
		if err != nil {
			return err
		}
		if relay && endpoint == "" && !reuseAnnounceHost {
			return errors.New("-relay needs -endpoint or -announce-port")
		}
		record.Relay = relay
		if delegationPublicKey != "" {
			key, err := readDelegationPublicKey(delegationPublicKey)
			if err != nil {
				return err
			}
			record.DelegationKey = delegationEncoding.EncodeToString(key)
		}
		mutation.Record = &record
		mutation.AnnouncePort = uint16(announcePort)
	}
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	request := struct {
		Method string                `json:"method"`
		Proxy  service.ProxyMutation `json:"proxy"`
	}{"proxy_capability", mutation}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	var reply struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Version uint64 `json:"version"`
	}
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		return err
	}
	if !reply.OK {
		return fmt.Errorf("proxy capability update failed: %s", reply.Error)
	}
	fmt.Printf("proxy capability version %d\n", reply.Version)
	return nil
}

func publication(certPath, endpoint string, ttl time.Duration, now time.Time) (service.ProxyCapability, error) {
	var value service.ProxyCapability
	if certPath == "" || ttl <= 0 {
		return value, errors.New("-tls-cert and a positive -ttl are required")
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return value, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return value, errors.New("expected a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return value, err
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return value, errors.New("proxy certificate is outside its validity period")
	}
	value = service.ProxyCapability{Active: true, ExpiresAt: now.Add(ttl).UTC(), SPKI: service.ProxyPublicKeyID(cert), Address: endpoint}
	if value.ExpiresAt.After(cert.NotAfter) {
		value.ExpiresAt = cert.NotAfter.UTC()
	}
	if endpoint != "" {
		value.Transport = service.ProxyTransport
	}
	return value, value.Validate()
}
