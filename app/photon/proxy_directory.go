package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func prepareProxyCapability(config *appConfig, mutation service.ProxyMutation) (service.ProxyMutation, error) {
	if mutation.AnnouncePort == 0 {
		return mutation, nil
	}
	if config == nil || mutation.Record == nil || mutation.Record.Address != "" || len(mutation.Record.Endpoints) != 0 || mutation.Record.Transport != "" {
		return mutation, errors.New("proxy announce port requires a publication without an explicit endpoint")
	}
	hosts := make(map[string]struct{})
	for _, address := range config.IPsec.AnnounceAddrs {
		hosts[address.Address] = struct{}{}
	}
	for _, dns := range config.IPsec.AnnounceDNS {
		hosts[dns.Host] = struct{}{}
	}
	if len(hosts) != 1 {
		return mutation, errors.New("-announce-port requires exactly one manual ipsec.announce_addrs or ipsec.announce_dns host; otherwise use -endpoint")
	}
	record := *mutation.Record
	for host := range hosts {
		record.Address = net.JoinHostPort(host, strconv.Itoa(int(mutation.AnnouncePort)))
	}
	record.Transport = service.ProxyTransport
	mutation.Record = &record
	mutation.AnnouncePort = 0
	return mutation, nil
}

func (d *Daemon) startProxyDirectory(ctx context.Context) (func(), error) {
	if d.Config == nil || d.Config.ProxyDirectorySocket == "" {
		return func() {}, nil
	}
	return startProxySocket(ctx, d.Config.ProxyDirectorySocket, d.writeProxyDirectory)
}

func (d *Daemon) startProxyPublisher(ctx context.Context) (func(), error) {
	if d.Config == nil || d.Config.ProxyPublishSocket == "" {
		return func() {}, nil
	}
	if d.Config.ProxyDirectorySocket == "" || d.Config.ProxyDirectorySocket == d.Config.ProxyPublishSocket {
		return nil, errors.New("proxy_publish_socket needs a distinct proxy_directory_socket")
	}
	return startProxySocket(ctx, d.Config.ProxyPublishSocket, func(conn net.Conn) {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var publication service.ProxyV2Publication
		decoder := json.NewDecoder(io.LimitReader(conn, service.ProxyDirectoryMaxBytes))
		decoder.DisallowUnknownFields()
		result := service.ProxyV2PublicationResult{}
		if err := decoder.Decode(&publication); err != nil {
			result.Error = err.Error()
		} else {
			requestCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			outcome := d.enqueueEvent(requestCtx, daemonEvent{
				Type: daemonEventCommonMutation, CommonIntent: corestate.ProxyV2Intent{Publication: publication},
			})
			result.OK = outcome.Error == nil
			if outcome.Error != nil {
				result.Error = outcome.Error.Error()
			}
		}
		_ = json.NewEncoder(conn).Encode(result)
	})
}

func startProxySocket(ctx context.Context, path string, serve func(net.Conn)) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := prepareControlSocketPath(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on proxy socket %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		var workers sync.WaitGroup
		defer workers.Wait()
		slots := make(chan struct{}, 8)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				workers.Go(func() {
					defer func() { <-slots }()
					serve(conn)
				})
			default:
				_ = conn.Close()
			}
		}
	}()
	return func() {
		stop()
		_ = listener.Close()
		<-done
	}, nil
}

func (d *Daemon) writeProxyDirectory(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	prefixes := []string{service.RecordKeyProxy}
	if d.Config.ProxyPublishSocket != "" {
		prefixes = append(prefixes, routing.RecordKeyPrefixRoutes, routing.RecordKeyPrefixIPAMAssignments,
			routing.RecordKeyPrefixIPAMPools, ipsec.RecordKeyAddresses)
	}
	view := d.State.Common.ReadDiscoveryRecordPrefixes("", prefixes...)
	if view == nil {
		return
	}
	directory := buildProxyDirectory(view.Network, d.now())
	if d.Config.ProxyPublishSocket != "" {
		directory.V2, directory.MeshPrefixes = buildProxyV2Directory(view.Network, view.ManagedZone, d.now())
	}
	directory.ManagedZone = view.ManagedZone
	data, err := json.Marshal(directory)
	if err == nil && len(data) < service.ProxyDirectoryMaxBytes {
		_, _ = conn.Write(data)
	}
}

func buildProxyDirectory(network *zone.NetworkState, now time.Time) service.ProxyDirectory {
	view := service.ProxyDirectory{ValidUntil: now.Add(service.ProxyDirectoryTTL), Peers: make(map[zone.ZonePath]service.ProxyCapability)}
	seen := make(map[string]zone.ZonePath)
	verifier := new(photoncrypto.Verifier)
	for owner, zs := range network.Zones {
		if zs == nil {
			continue
		}
		raw := zs.Records[service.RecordKeyProxy]
		if raw == nil || raw.Zone != owner {
			continue
		}
		record, err := service.ParseProxyCapability(raw)
		if err != nil || !record.Active || !record.ExpiresAt.After(now) ||
			verifier.VerifyChain(network, owner, now) != nil || verifier.VerifyRecord(raw, zs.Authority, now) != nil {
			continue
		}
		if record.SPKI != "" {
			if previous, ok := seen[record.SPKI]; ok {
				delete(view.Peers, previous)
				continue
			}
			seen[record.SPKI] = owner
		}
		view.Peers[owner] = record
	}
	return view
}
