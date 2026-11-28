package photonproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
)

const (
	v2ConnectivityURL = "https://www.google.com/generate_204"
	v2DNSAddress      = "1.1.1.1:53"
	v2DownloadURL     = "https://speed.cloudflare.com/__down?bytes=4194304"
	v2DownloadBytes   = 4 * 1024 * 1024
	v2QuickTimeout    = 8 * time.Second
	v2DownloadTimeout = 60 * time.Second
)

type v2ProbeRequest struct {
	Kind     string   `json:"kind,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Target   string   `json:"target,omitempty"`
	Hops     []string `json:"hops,omitempty"`
}

type v2ProbeResult struct {
	OK           bool    `json:"ok"`
	ElapsedMS    int64   `json:"elapsed_ms"`
	Error        string  `json:"error,omitempty"`
	FailedHop    *int    `json:"failed_hop,omitempty"`
	HTTPStatus   int     `json:"http_status,omitempty"`
	Bytes        int64   `json:"bytes,omitempty"`
	TransferMS   int64   `json:"transfer_ms,omitempty"`
	DownloadMbps float64 `json:"download_mbps,omitempty"`
}

func (r v2ProbeRequest) timeout(saved bool) (time.Duration, error) {
	if r.Kind == "" {
		return v2QuickTimeout, nil
	}
	if !saved || len(r.Hops) != 0 || r.Protocol != "" || r.Target != "" {
		return 0, errors.New("probe presets require a saved route and no custom target")
	}
	switch r.Kind {
	case "connectivity", "dns":
		return v2QuickTimeout, nil
	case "download":
		return v2DownloadTimeout, nil
	default:
		return 0, fmt.Errorf("unknown probe preset %q", r.Kind)
	}
}

func probeV2(ctx context.Context, opener tunnelOpener, request v2ProbeRequest) v2ProbeResult {
	start := time.Now()
	var result v2ProbeResult
	var err error
	switch request.Kind {
	case "connectivity":
		err = probeV2HTTPS(ctx, opener, v2ConnectivityURL, http.StatusNoContent, 0, nil, &result)
	case "download":
		err = probeV2HTTPS(ctx, opener, v2DownloadURL, http.StatusOK, v2DownloadBytes, nil, &result)
	case "dns":
		err = probeV2UDP(ctx, opener, netip.MustParseAddrPort(v2DNSAddress))
	case "":
		err = probeV2Target(ctx, opener, request.Protocol, request.Target)
	default:
		err = fmt.Errorf("unknown probe preset %q", request.Kind)
	}
	result.OK = err == nil
	result.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		var hop *v2HopError
		result.Error = err.Error()
		if errors.As(err, &hop) && hop.index >= 0 {
			result.FailedHop = &hop.index
		}
	}
	return result
}

func probeV2Target(ctx context.Context, opener tunnelOpener, protocol, target string) error {
	switch protocol {
	case "", "tcp":
		if _, err := splitTarget(target); err != nil {
			return err
		}
		stream, err := opener.open(ctx, target)
		if err == nil {
			_ = stream.Close()
		}
		return err
	case "udp":
		destination, err := netip.ParseAddrPort(target)
		if err != nil {
			return err
		}
		if destination.Port() == 0 {
			return errors.New("invalid DNS probe port")
		}
		return probeV2UDP(ctx, opener, destination)
	default:
		return errors.New("protocol must be tcp or udp")
	}
}

// Only the saved route's opener dials the target. Verify the public site's
// TLS identity and read the expected response without following redirects.
func probeV2HTTPS(ctx context.Context, opener tunnelOpener, url string, status int, size int64, config *tls.Config, result *v2ProbeResult) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if request.URL.Scheme != "https" || request.URL.Hostname() == "" {
		return errors.New("probe requires an HTTPS target")
	}
	request.Close = true
	request.Header.Set("Accept-Encoding", "identity")
	port := request.URL.Port()
	if port == "" {
		port = "443"
	}
	host := request.URL.Hostname()
	stream, err := opener.open(ctx, net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	conn := tunnelStreamConn(ctx, stream, nil)
	defer conn.Close()
	if config == nil {
		config = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		config = config.Clone()
	}
	config.ServerName = host
	secure := tls.Client(conn, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("HTTPS handshake: %w", err)
	}
	if err := request.Write(secure); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), request)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
		_ = response.Body.Close()
	}()
	result.HTTPStatus = response.StatusCode
	if response.StatusCode != status {
		return fmt.Errorf("HTTP %d, expected %d", response.StatusCode, status)
	}
	if size == 0 {
		return nil
	}
	start := time.Now()
	result.Bytes, err = io.Copy(io.Discard, io.LimitReader(response.Body, size+1))
	duration := time.Since(start)
	result.TransferMS = duration.Milliseconds()
	if err != nil {
		return err
	}
	if result.Bytes != size {
		return fmt.Errorf("received %d bytes, expected %d", result.Bytes, size)
	}
	if duration > 0 {
		result.DownloadMbps = float64(result.Bytes) * 8 / duration.Seconds() / 1e6
	}
	return nil
}

func probeV2UDP(ctx context.Context, opener tunnelOpener, target netip.AddrPort) error {
	stream, err := opener.open(ctx, trusttunnel.UDPAuthority)
	if err != nil {
		return err
	}
	defer stream.Close()
	// DNS A query for example.com.
	payload := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := rand.Read(payload[:2]); err != nil {
		return err
	}
	source := netip.MustParseAddrPort("127.0.0.1:49152")
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if err := trusttunnel.WriteRequest(stream, trusttunnel.Datagram{Source: source, Destination: target, Payload: payload}); err != nil {
		return err
	}
	for {
		reply, err := trusttunnel.ReadResponse(stream)
		if err != nil {
			return err
		}
		if reply.Source != target || reply.Destination != source || len(reply.Payload) < 12 ||
			binary.BigEndian.Uint16(reply.Payload) != binary.BigEndian.Uint16(payload) || reply.Payload[2]&0x80 == 0 {
			continue
		}
		if code := reply.Payload[3] & 0x0f; code != 0 {
			return fmt.Errorf("DNS returned RCODE %d", code)
		}
		if binary.BigEndian.Uint16(reply.Payload[6:8]) == 0 {
			return errors.New("DNS reply has no answer")
		}
		return nil
	}
}
