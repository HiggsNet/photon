package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
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
	epoch := rand.Text()
	return startProxySocket(ctx, d.Config.ProxyDirectorySocket, func(conn net.Conn) {
		d.writeProxyData(conn, epoch)
	})
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

func (d *Daemon) writeProxyData(conn net.Conn, epoch string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	var request service.ProxyReadRequest
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&request); err != nil {
		return
	}
	reply := service.ProxyReadResponse{Epoch: epoch}
	switch request.Kind {
	case service.ProxyReadDirectory:
		store := d.State.Common
		reply.Revision = uint64(store.VerifiedRevision())
		if request.Epoch != epoch || request.Revision != reply.Revision {
			view := store.ReadDiscoveryRecordPrefixes("", service.RecordKeyProxy,
				routing.RecordKeyPrefixRoutes, routing.RecordKeyPrefixIPAMAssignments, routing.RecordKeyPrefixIPAMPools,
				ipsec.RecordKeyAddresses)
			if view == nil {
				return
			}
			reply.Revision = uint64(view.Revision)
			reply.ManagedZone, reply.Network = view.ManagedZone, view.Network
		}
	case service.ProxyReadLinks:
		reply.Links = d.proxyDirectLinks()
	default:
		return
	}
	data, err := json.Marshal(reply)
	if err == nil && len(data) < service.ProxyReadMaxBytes {
		_, _ = conn.Write(data)
	}
}

func (d *Daemon) proxyDirectLinks() []service.ProxyDirectLink {
	instances, observation := d.linuxObservation.ipsecSnapshot()
	if observation == nil {
		return nil
	}
	type sessionKey struct {
		name string
		id   uint32
	}
	families := make(map[sessionKey]string)
	for _, sa := range observation.ActualSAs {
		if !sa.Established || sa.Name == "" || sa.XFRMIfID == 0 || !strings.EqualFold(sa.ChildState, "INSTALLED") {
			continue
		}
		remote, _, err := net.SplitHostPort(sa.RemoteEndpoint)
		if err != nil {
			remote = sa.RemoteEndpoint
		}
		address, err := netip.ParseAddr(remote)
		if err != nil {
			if endpoint, err := netip.ParseAddrPort(sa.Endpoint); err == nil {
				address = endpoint.Addr()
			}
		}
		if !address.IsValid() {
			continue
		}
		family := "ipv6"
		if address.Unmap().Is4() {
			family = "ipv4"
		}
		families[sessionKey{sa.Name, sa.XFRMIfID}] = family
	}
	byID := make(map[string]ipsec.LinkInstance, len(instances))
	for _, instance := range instances {
		id := instance.LinkID
		if id == "" {
			id = instance.ID
		}
		byID[id] = instance
	}
	var links []service.ProxyDirectLink
	for _, link := range buildLinkOutputs(instances, observation) {
		if link.Readiness.Session != photonstate.LinkReadyReady || link.InterfaceName == "" ||
			!link.LocalAddr.Is6() || !link.LocalAddr.IsLinkLocalUnicast() ||
			!link.PeerAddr.Is6() || !link.PeerAddr.IsLinkLocalUnicast() {
			continue
		}
		staged := link.RuntimeRole == photonstate.LinkRuntimeStaged
		id := strings.TrimSuffix(link.ID, "#"+photonstate.LinkRuntimeStaged)
		instance, ok := byID[id]
		if !ok {
			continue
		}
		session := sessionKey{instance.IKEName, instance.XFRMIfID}
		if staged {
			session = sessionKey{instance.StagedIKEName, instance.StagedXFRMIfID}
		}
		family := families[session]
		if family == "" || family != photonstate.LinkPathFamily(link.PathKey) {
			continue
		}
		links = append(links, service.ProxyDirectLink{
			ID: id, Peer: link.PeerZone, Family: family, Generation: link.Generation, Staged: staged,
			NetNS: link.NetNS, Interface: link.InterfaceName, Local: link.LocalAddr, Remote: link.PeerAddr,
		})
	}
	return links
}
