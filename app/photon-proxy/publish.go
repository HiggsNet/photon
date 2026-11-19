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
	"strings"
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
	var ttl, interval time.Duration
	var announcePort uint
	var relay bool
	var delegationPublicKey string
	endpoints := make(map[string]string)
	renew := command == "renew"
	if command != "withdraw" {
		flags.StringVar(&cert, "tls-cert", "", "PEM proxy certificate (public part)")
		flags.StringVar(&endpoint, "endpoint", "", "reachable TCP host:port (omit for a client-only node)")
		flags.Func("endpoint-choice", "chain endpoint as public-v4, public-v6 or photon=host:port (repeatable)", func(value string) error {
			return addEndpointChoice(endpoints, value)
		})
		flags.UintVar(&announcePort, "announce-port", 0, "TCP port to publish with the single manual IPsec announce host")
		flags.BoolVar(&relay, "relay", false, "publish the endpoint as a relay instead of an exit")
		flags.StringVar(&delegationPublicKey, "delegation-pubkey", "", "PEM Ed25519 public key for signed delegation")
		flags.DurationVar(&ttl, "ttl", 24*time.Hour, "capability lifetime")
	}
	if renew {
		flags.DurationVar(&interval, "interval", 0, "check repeatedly at this interval (0 checks once)")
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
	if interval < 0 || (interval > 0 && mutation.ExpectedVersion != nil) {
		return errors.New("use a positive -interval without -expect-version for repeated renewals")
	}
	method := "proxy_capability"
	if renew {
		method = "proxy_renew"
	}
	if command != "withdraw" {
		if reuseAnnounceHost && (announcePort == 0 || announcePort > 65535 || endpoint != "" || len(endpoints) != 0) {
			return errors.New("-announce-port requires a valid port and cannot be combined with explicit endpoints")
		}
		if ttl <= 0 || (cert == "" && (endpoint != "" || len(endpoints) != 0 || reuseAnnounceHost || delegationPublicKey == "")) {
			return errors.New("a positive -ttl and -tls-cert are required, except for a signing-only client")
		}
		if relay && endpoint == "" && len(endpoints) == 0 && !reuseAnnounceHost {
			return errors.New("-relay needs an endpoint")
		}
		mutation.AnnouncePort = uint16(announcePort)
	}

	attempt := func() error {
		if command != "withdraw" {
			record, err := publication(cert, endpoint, ttl, time.Now())
			if err != nil {
				return err
			}
			record.Relay = relay
			if len(endpoints) != 0 {
				record.Endpoints = endpoints
				record.Transport = service.ProxyTransport
			}
			if delegationPublicKey != "" {
				key, err := readDelegationPublicKey(delegationPublicKey)
				if err != nil {
					return err
				}
				record.DelegationKey = delegationEncoding.EncodeToString(key)
			}
			if !reuseAnnounceHost {
				if err := record.Validate(); err != nil {
					return err
				}
			}
			mutation.Record = &record
		}
		version, err := sendProxyMutation(ctx, *socket, method, mutation)
		if err != nil {
			return err
		}
		if version == 0 {
			fmt.Println("no matching active proxy capability")
		} else {
			fmt.Printf("proxy capability version %d\n", version)
		}
		return nil
	}
	if interval == 0 {
		return attempt()
	}
	for ctx.Err() == nil {
		wait := interval
		if err := attempt(); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "photon-proxy renew:", err)
			wait = min(interval, time.Minute)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func addEndpointChoice(endpoints map[string]string, value string) error {
	name, address, ok := strings.Cut(value, "=")
	if !ok {
		return errors.New("expected a proxy endpoint as name=host:port")
	}
	if _, exists := endpoints[name]; exists {
		return fmt.Errorf("duplicate proxy endpoint %q", name)
	}
	if err := service.ValidateProxyEndpoint(name, address); err != nil {
		return err
	}
	endpoints[name] = address
	return nil
}

func sendProxyMutation(ctx context.Context, socket, method string, mutation service.ProxyMutation) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	request := struct {
		Method string                `json:"method"`
		Proxy  service.ProxyMutation `json:"proxy"`
	}{method, mutation}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return 0, err
	}
	var reply struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Version uint64 `json:"version"`
	}
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		return 0, err
	}
	if !reply.OK {
		return 0, fmt.Errorf("proxy capability update failed: %s", reply.Error)
	}
	return reply.Version, nil
}

func publication(certPath, endpoint string, ttl time.Duration, now time.Time) (service.ProxyCapability, error) {
	value := service.ProxyCapability{Active: true, ExpiresAt: now.Add(ttl).UTC(), Address: endpoint}
	if certPath == "" {
		return value, nil
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
	value.SPKI = service.ProxyPublicKeyID(cert)
	if value.ExpiresAt.After(cert.NotAfter) {
		value.ExpiresAt = cert.NotAfter.UTC()
	}
	if endpoint != "" {
		value.Transport = service.ProxyTransport
	}
	return value, nil
}
