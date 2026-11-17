package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	service "github.com/HiggsNet/photon/pkg/service"
)

// The health stream alone cannot establish UDP egress readiness. Use an actual
// framed UDP exchange over HTTP/3, with the published certificate and no TCP
// fallback. curl's nonblocking stdin mode lets the response arrive before EOF.
func trustTunnelUDPExchange(endpoint resolvedEndpoint, name, cert string, target *net.UDPAddr, payload []byte, timeout time.Duration) ([]byte, error) {
	if len(payload) > 65535 || target.IP.To16() == nil || target.Port < 1 || target.Port > 65535 {
		return nil, errors.New("invalid trusttunnel UDP target or payload")
	}
	frame := make([]byte, 41+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(frame)-4))
	if v4 := target.IP.To4(); v4 != nil {
		copy(frame[34:38], v4)
	} else {
		copy(frame[22:38], target.IP.To16())
	}
	binary.BigEndian.PutUint16(frame[38:40], uint16(target.Port))
	copy(frame[41:], payload)
	address := endpoint.Address
	if strings.Contains(address, ":") {
		address = "[" + address + "]"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	auth := base64.StdEncoding.EncodeToString([]byte(service.TrustTunnelUser + ":"))
	cmd := exec.CommandContext(ctx, "curl", "--noproxy", "*", "--http3-only", "--silent", "--show-error", "--fail", "--no-buffer", "--cacert", cert, "--resolve", fmt.Sprintf("%s:%d:%s", name, endpoint.Port, address), "--request", "CONNECT", "--request-target", "_udp2", "--header", "Proxy-Authorization: Basic "+auth, "--upload-file", ".", fmt.Sprintf("https://%s:%d/", name, endpoint.Port))
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() { input.Close(); cancel(); _ = cmd.Wait() }()
	if _, err := input.Write(frame); err != nil {
		return nil, err
	}
	header := make([]byte, 40)
	if _, err := io.ReadFull(output, header); err != nil {
		return nil, fmt.Errorf("HTTP/3 UDP response: %w (context: %v)", err, ctx.Err())
	}
	length := int(binary.BigEndian.Uint32(header[:4])) - 36
	if length < 0 || length > 65535 {
		return nil, errors.New("invalid trusttunnel UDP response length")
	}
	source := net.IP(header[4:20])
	if bytes.Equal(header[4:16], make([]byte, 12)) {
		source = net.IP(header[16:20])
	}
	if !source.Equal(target.IP) || int(binary.BigEndian.Uint16(header[20:22])) != target.Port {
		return nil, errors.New("trusttunnel UDP response source mismatch")
	}
	response := make([]byte, length)
	_, err = io.ReadFull(output, response)
	return response, err
}

func checkTrustTunnelUDPDNS(endpoint resolvedEndpoint, name, cert string, resolver resolverConfig) error {
	targets, err := udpDNSProbeTargets(resolver.Servers)
	if err != nil {
		return err
	}
	var failures []error
	for attempt := 0; attempt < udpDNSReadinessAttempts; attempt++ {
		for _, target := range targets {
			query, id, err := dnsHealthQuery()
			if err != nil {
				return err
			}
			response, err := trustTunnelUDPExchange(endpoint, name, cert, target, query, 5*time.Second)
			if err == nil && len(response) >= 12 && binary.BigEndian.Uint16(response[:2]) == id && response[2]&0x80 != 0 && response[3]&0x0f == 0 && binary.BigEndian.Uint16(response[6:8]) != 0 {
				return nil
			}
			failures = append(failures, fmt.Errorf("UDP DNS via %s: %v", target, err))
		}
	}
	return fmt.Errorf("trusttunnel UDP DNS readiness failed: %w", errors.Join(failures...))
}
