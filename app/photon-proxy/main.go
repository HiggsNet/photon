package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	setupTimeout = 10 * time.Second
	sessionLimit = 128
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "photon-proxy:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "Usage: photon-proxy serve|socks5|publish|withdraw [options]")
		return flag.ErrHelp
	}
	switch args[0] {
	case "serve":
		return runServer(ctx, args[1:])
	case "socks5":
		return runSOCKS(ctx, args[1:])
	case "publish", "withdraw":
		return runPublication(ctx, args[0], args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runServer(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("photon-proxy serve", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8443", "TrustTunnel HTTP/2 listen address")
	cert := flags.String("tls-cert", "", "PEM server certificate chain")
	key := flags.String("tls-key", "", "PEM server private key")
	ca := flags.String("client-ca", "", "PEM roots for authorized client certificates")
	allow := flags.String("allow", "", "comma-separated destination IP prefixes allowed for these clients")
	socket := flags.String("directory-socket", "", "local Photon read-only proxy directory socket")
	zones := flags.String("allow-zones", "", "comma-separated client Zones permitted in directory mode")
	delegates := flags.String("allow-delegates", "", "comma-separated relay Zones allowed to present signed grants")
	delegationEndpoint := flags.String("delegation-endpoint", "", "this exit's advertised host:port for signed grants")
	relayServerCA := flags.String("relay-server-ca", "", "enable signed forwarding from this relay; PEM CA for its exits")
	relay := make(relayTargets)
	flags.Func("relay-target", "run as relay; permitted next hop as Zone=host:port (repeatable)", relay.add)
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if (*delegates == "") != (*delegationEndpoint == "") || (*delegates != "" && (len(relay) != 0 || *socket == "")) {
		return errors.New("an exit needs both -allow-delegates and -delegation-endpoint with a directory socket")
	}
	if *relayServerCA != "" && len(relay) == 0 {
		return errors.New("-relay-server-ca requires -relay-target")
	}
	var allowed []netip.Prefix
	if len(relay) == 0 {
		var err error
		allowed, err = parseAllowed(*allow)
		if err != nil {
			return err
		}
	} else if *allow != "" || *socket == "" || *zones == "" {
		return errors.New("-relay-target requires -directory-socket and -allow-zones; -allow is for an exit")
	}
	config, roots, err := loadTLS(*cert, *key, *ca)
	if err != nil {
		return err
	}
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.ClientCAs = roots
	if (*socket == "") != (*zones == "") {
		return errors.New("-directory-socket and -allow-zones must be used together")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var access *zoneAccess
	var verifier *delegationVerifier
	var signedRelay *delegatedRelay
	if *socket != "" {
		allowedZones, err := parseProxyZones(*zones)
		if err != nil {
			return err
		}
		directory, err := openProxyDirectory(ctx, *socket)
		if err != nil {
			return fmt.Errorf("read proxy directory: %w", err)
		}
		access = &zoneAccess{directory: directory, allowed: allowedZones}
		if *delegates != "" {
			access.delegates, err = parseProxyZones(*delegates)
			if err != nil {
				return err
			}
			if _, err := splitTarget(*delegationEndpoint); err != nil {
				return fmt.Errorf("-delegation-endpoint: %w", err)
			}
			verifier = &delegationVerifier{endpoint: *delegationEndpoint, started: time.Now()}
		}
		config.VerifyConnection = access.verify
	}
	if *relayServerCA != "" {
		roots, err := loadPeerCA(*relayServerCA)
		if err != nil {
			return err
		}
		signedRelay = &delegatedRelay{tls: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: config.Certificates, RootCAs: roots,
		}}
		defer signedRelay.closeIdleConnections()
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	return serveTunnel(ctx, listener, config, &tunnelHandler{allowed: allowed, access: access, relay: relay, verifier: verifier, delegatedRelay: signedRelay})
}

func runSOCKS(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("photon-proxy socks5", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:1080", "local SOCKS5 listen address (loopback only)")
	server := flags.String("server", "", "remote TrustTunnel host:port")
	serverZone := flags.String("server-zone", "", "discover a TrustTunnel endpoint for this Zone")
	viaZone := flags.String("via-zone", "", "connect to the server Zone through this relay Zone")
	relayServerName := flags.String("relay-server-name", "", "expected relay certificate name (defaults to relay host)")
	socket := flags.String("directory-socket", "", "local Photon read-only proxy directory socket")
	serverName := flags.String("server-name", "", "expected server certificate name (defaults to server host)")
	ca := flags.String("server-ca", "", "PEM roots for the remote server")
	cert := flags.String("tls-cert", "", "PEM client certificate chain")
	key := flags.String("tls-key", "", "PEM client private key")
	authFile := flags.String("auth-file", "", "optional TrustTunnel Basic credentials (username:password file)")
	delegationKey := flags.String("delegation-key", "", "PEM Ed25519 private key for signed forwarding through -via-zone")
	udpScope := flags.String("delegation-udp-prefixes", "", "comma-separated destinations for each signed UDP association")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if (*server == "") == (*serverZone == "") || (*serverZone == "") != (*socket == "") {
		return errors.New("use -server or -server-zone with -directory-socket")
	}
	via := zone.ZonePath(*viaZone)
	if (via != "" && (!via.Valid() || *serverZone == "" || *viaZone == *serverZone)) || (*relayServerName != "" && via == "") {
		return errors.New("-via-zone must name a relay Zone different from -server-zone")
	}
	if (*delegationKey != "" && (via == "" || *authFile != "" || *serverName != "")) || (*udpScope != "" && *delegationKey == "") {
		return errors.New("signed delegation requires -via-zone and is configured through the advertised exit endpoint")
	}
	var signingKey ed25519.PrivateKey
	if *delegationKey != "" {
		var err error
		signingKey, err = readDelegationPrivateKey(*delegationKey)
		if err != nil {
			return err
		}
	}
	var udpPrefixes string
	if *udpScope != "" {
		prefixes, err := parseAllowed(*udpScope)
		if err != nil {
			return err
		}
		parts := make([]string, 0, len(prefixes))
		for _, prefix := range prefixes {
			parts = append(parts, prefix.String())
		}
		udpPrefixes = strings.Join(parts, ",")
	}
	listenHost, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	listenIP, err := netip.ParseAddr(listenHost)
	if err != nil || !listenIP.IsLoopback() {
		return errors.New("SOCKS5 -listen must use a loopback IP")
	}
	config, roots, err := loadTLS(*cert, *key, *ca)
	if err != nil {
		return err
	}
	config.RootCAs = roots
	authorization, err := loadAuthorization(*authFile)
	if err != nil {
		return err
	}
	config.ServerName = *serverName
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var client tunnelOpener
	if *serverZone != "" {
		path := zone.ZonePath(*serverZone)
		if !path.Valid() {
			return fmt.Errorf("invalid server Zone %q", *serverZone)
		}
		directory, err := openProxyDirectory(ctx, *socket)
		if err != nil {
			return fmt.Errorf("read proxy directory: %w", err)
		}
		dynamic := &zoneTunnelClient{
			directory: directory, zone: path, via: via, relayServerName: *relayServerName, tls: config, auth: authorization,
			delegation: signingKey, delegationUDP: udpPrefixes,
		}
		defer dynamic.closeIdleConnections()
		client = dynamic
	} else {
		host, err := splitTarget(*server)
		if err != nil {
			return fmt.Errorf("-server: %w", err)
		}
		if config.ServerName == "" {
			config.ServerName = host
		}
		fixed := newTunnelClient(*server, config)
		fixed.authorization = authorization
		defer fixed.closeIdleConnections()
		client = fixed
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	return serveSOCKS(ctx, listener, client)
}

func loadAuthorization(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	user, _, ok := strings.Cut(line, ":")
	if !ok || user == "" || strings.ContainsAny(line, "\r\n") {
		return "", errors.New("-auth-file must contain a single username:password line")
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(line)), nil
}

func parseFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return nil
}

func loadTLS(certFile, keyFile, caFile string) (*tls.Config, *x509.CertPool, error) {
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, nil, errors.New("TLS certificate, private key and peer CA are required")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	roots, err := loadPeerCA(caFile)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, roots, nil
}

func loadPeerCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return roots, nil
}

func parseProxyZones(value string) ([]zone.ZonePath, error) {
	var out []zone.ZonePath
	for _, name := range strings.Split(value, ",") {
		path := zone.ZonePath(strings.TrimSpace(name))
		if !path.Valid() {
			return nil, fmt.Errorf("invalid proxy Zone %q", name)
		}
		out = append(out, path)
	}
	return out, nil
}

func http2Only() *http.Protocols {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	return protocols
}

func parseAllowed(value string) ([]netip.Prefix, error) {
	if value == "" {
		return nil, errors.New("-allow requires at least one destination prefix")
	}
	var prefixes []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid -allow prefix %q", item)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
