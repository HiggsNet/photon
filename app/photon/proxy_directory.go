package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/service"
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
	path := d.Config.ProxyDirectorySocket
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := prepareControlSocketPath(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on proxy directory socket: %w", err)
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
					d.writeProxyDirectory(conn)
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
	view := d.State.Common.ReadDiscoveryRecords("", service.RecordKeyProxy)
	if view == nil {
		return
	}
	directory := buildProxyDirectory(view.Network, d.now())
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
