package photonproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
)

const v2LeaseDuration = 24 * time.Hour

type v2Node struct {
	ctx             context.Context
	host            Host
	config          v2Config
	db              *routeState
	state           v2DiskState
	key             ed25519.PrivateKey
	directory       *proxyDirectory
	pool            *v2DialPool
	server          *v2Server
	certificate     atomic.Pointer[tls.Certificate]
	listeners       map[v2ListenerKey][]*v2Listener
	workers         sync.WaitGroup
	errors          chan error
	lastPublication time.Time
	lastMesh        map[string]bool
}

func runV2(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("photon-proxy run", flag.ContinueOnError)
	path := flags.String("config", "", "unified Photon Proxy v2 YAML configuration")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("run requires -config")
	}
	config, err := readV2Config(*path)
	if err != nil {
		return err
	}
	return runV2Node(ctx, config, Host{
		Read: func(ctx context.Context, request service.ProxyReadRequest) (service.ProxyReadResponse, error) {
			return readProxyData(ctx, config.DirectorySocket, request)
		},
		Publish: func(ctx context.Context, publication service.ProxyV2Publication) error {
			return sendV2Publication(ctx, config.PublishSocket, publication)
		},
	})
}

func runV2Node(ctx context.Context, config v2Config, host Host) error {
	if err := prepareV2StateDir(config.StateDir); err != nil {
		return err
	}
	var initial map[string]clientRoute
	if config.Client != nil {
		initial = config.Client.Routes
	}
	db, routes, err := openRouteState(filepath.Join(config.StateDir, "state.db"), initial)
	if err != nil {
		return err
	}
	defer db.Close()
	state, err := db.loadV2()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	directory, err := openDirectory(ctx, host.Read, config.DirectoryRefresh)
	if err != nil {
		cancel()
		return err
	}
	if !directory.managedZone().Valid() || directory.managedZone().IsRoot() {
		cancel()
		return errors.New("Photon Proxy requires an initialized non-root Zone")
	}
	node := &v2Node{ctx: ctx, config: config, db: db, state: state, directory: directory, host: host,
		pool: &v2DialPool{publicDevice: config.PublicDevice, meshDevice: config.PhotonDevice,
			dialPeer: host.DialPeer, lookupPeer: host.LookupPeer},
		listeners: make(map[v2ListenerKey][]*v2Listener), errors: make(chan error, 1)}
	defer func() {
		cancel()
		for _, servers := range node.listeners {
			for _, server := range servers {
				_ = server.http.Close()
				_ = server.listener.Close()
			}
		}
		node.workers.Wait()
		node.pool.close()
	}()
	if namespace, enabled := config.directNamespace(); enabled || host.DialDirect != nil {
		node.pool.directLinks = &directLinks{namespace: namespace, scoped: host.DialDirect != nil}
		node.pool.direct = &directPool{ctx: ctx, dial: host.DialDirect, entries: make(map[directPoolKey]*directPoolEntry)}
		node.pool.directLinks.refresh(ctx, host.Read)
		node.workers.Go(func() {
			node.pool.directLinks.run(ctx, host.Read, func() {
				node.pool.direct.warmStaged(directory.snapshotV2(), node.pool.directLinks.current())
			})
		})
	}
	if err := node.start(); err != nil {
		return err
	}
	var routeErrors <-chan error
	if config.Client != nil {
		manager, err := node.startClient(routes)
		if err != nil {
			return err
		}
		defer manager.close()
		routeErrors = manager.errors
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			stopCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer stop()
			if err := host.Publish(stopCtx, service.ProxyV2Publication{Replace: true}); err != nil {
				log.Printf("withdraw Photon Proxy publication on shutdown: %v", err)
			}
			return nil
		case err := <-node.errors:
			return err
		case err := <-routeErrors:
			return err
		case <-ticker.C:
			if err := node.tick(); err != nil {
				log.Printf("Photon Proxy reconciliation: %v", err)
			}
		}
	}
}

func (n *v2Node) report(err error) {
	select {
	case n.errors <- err:
	default:
	}
}

func (n *v2Node) start() error {
	now := time.Now()
	if n.config.Client != nil && len(n.state.SigningKey) == 0 {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		n.state.SigningKey = key
	}
	if n.config.Client != nil && len(n.state.SigningKey) != ed25519.PrivateKeySize {
		return errors.New("invalid persisted route signing key")
	}
	n.key = ed25519.PrivateKey(n.state.SigningKey)
	var replay *v2Replay
	if len(n.config.PortGroups) > 0 {
		var err error
		replay, err = newV2Replay(n.db, now, len(n.state.TLS.Current.Cert) != 0)
		if err != nil {
			return err
		}
		if len(n.state.TLS.Current.Cert) == 0 {
			material, err := makeV2TLS(now, n.config.TLS.Lifetime, nil)
			if err != nil {
				return err
			}
			n.state.TLS.Current = material
		}
		if err := n.refreshTLS(now); err != nil {
			return err
		}
	}
	for group := range n.state.Ports {
		if _, ok := n.config.PortGroups[group]; !ok {
			delete(n.state.Ports, group)
			delete(n.state.Activated, group)
		}
	}
	for group := range n.state.Pending {
		if _, ok := n.config.PortGroups[group]; !ok {
			delete(n.state.Pending, group)
		}
	}
	fresh := make(map[string]bool)
	for group, config := range n.config.PortGroups {
		set := n.state.Ports[group]
		_, pending := n.state.Pending[group]
		if config.Port != 0 && (set.Current.Port != config.Port || set.Previous != nil || pending) ||
			config.Port == 0 && (set.Current.Port < config.Range[0] || set.Current.Port > config.Range[1]) {
			port := config.Port
			if port == 0 {
				port = config.Range[0]
			}
			set = service.ProxyV2Ports{Current: service.ProxyV2Port{Generation: set.Current.Generation + 1, Port: port}}
			n.state.Ports[group] = set
			delete(n.state.Pending, group)
			n.state.Activated[group] = now
			fresh[group] = true
		}
	}
	_, policies, err := n.config.v2Endpoints(n.desiredPorts())
	if err != nil {
		return err
	}
	n.server = &v2Server{directory: n.directory, pool: n.pool, endpoints: policies, dialExit: n.host.DialExit,
		replay: replay, slots: make(chan struct{}, sessionLimit)}
	n.updateInternalNetworks()
	for _, ports := range []map[string]service.ProxyV2Ports{n.state.Ports, n.state.Pending} {
		for group, set := range ports {
			toBind := []uint16{set.Current.Port}
			if set.Previous != nil {
				toBind = append(toBind, set.Previous.Port)
			}
			for _, port := range toBind {
				key := v2ListenerKey{group, port}
				if _, ok := n.listeners[key]; ok {
					continue
				}
				listeners, err := n.listen(key)
				config := n.config.PortGroups[group]
				if err != nil && fresh[group] && len(config.Range) == 2 && port == set.Current.Port {
					for candidate := int(config.Range[0]); candidate <= int(config.Range[1]) && err != nil; candidate++ {
						if uint16(candidate) == port {
							continue
						}
						key.port = uint16(candidate)
						listeners, err = n.listen(key)
					}
					if err == nil {
						set.Current.Port = key.port
						ports[group] = set
					}
				}
				if err != nil {
					return fmt.Errorf("proxy port group %s, port %d: %w", group, port, err)
				}
				n.listeners[key] = listeners
			}
		}
	}
	if err := n.db.saveV2(n.state); err != nil {
		return err
	}
	return n.publish()
}

func (n *v2Node) startClient(routes map[string]clientRoute) (*routeManager, error) {
	client := n.config.Client
	prefixes, _ := parseV2SourcePrefixes(client.AllowedSources)
	if routes == nil {
		routes = make(map[string]clientRoute)
	}
	for name, route := range client.Routes {
		if _, ok := routes[name]; !ok {
			routes[name] = route
		}
	}
	manager := newRouteManager(n.ctx, n.db, func(entry clientEntry) *v2Client {
		return &v2Client{directory: n.directory, pool: n.pool, key: n.key, route: entry.v2Route, udp: entry.udp}
	})
	manager.prepare = v2PrepareEntry(n.directory.managedZone(), len(prefixes) != 0)
	manager.defaultListen = client.DefaultListen
	manager.allowSource = func(ip netip.Addr) bool {
		return len(prefixes) == 0 && ip.IsLoopback() || withinPrefixes(ip, prefixes)
	}
	var entries []clientEntry
	for _, name := range slices.Sorted(maps.Keys(routes)) {
		route := routes[name]
		if route.Listen == "" {
			route.Listen = client.DefaultListen
			routes[name] = route
		}
		entry, err := manager.prepare(name, route, true)
		if err != nil {
			manager.close()
			return nil, fmt.Errorf("route %q: %w", name, err)
		}
		entries = append(entries, entry)
	}
	if err := manager.start(routes, entries); err != nil {
		manager.close()
		return nil, err
	}
	if err := n.startV2Admin(manager); err != nil {
		manager.close()
		return nil, err
	}
	return manager, nil
}

func (n *v2Node) desiredPorts() map[string]service.ProxyV2Ports {
	ports := maps.Clone(n.state.Ports)
	maps.Copy(ports, n.state.Pending)
	return ports
}

func (n *v2Node) publish() error {
	now := time.Now()
	ports := n.desiredPorts()
	endpoints, _, err := n.config.v2Endpoints(ports)
	if err != nil {
		return err
	}
	lease := service.ProxyV2Lease{Active: true, ExpiresAt: now.Add(v2LeaseDuration).Unix()}
	var publication service.ProxyV2Publication
	publication.Replace = true
	add := func(key, kind string, value any) error {
		raw, err := json.Marshal(value)
		if err == nil {
			publication.Records = append(publication.Records, service.ProxyV2Record{Key: key, Type: kind, Value: raw})
		}
		return err
	}
	if n.config.Client != nil {
		if err := add(service.ProxyV2IdentityKey, service.ProxyV2IdentityType, service.ProxyV2Identity{
			ProxyV2Lease: lease, PublicKey: delegationEncoding.EncodeToString(n.key.Public().(ed25519.PublicKey)),
		}); err != nil {
			return err
		}
	}
	mesh := n.checkMeshAddresses(ports)
	if len(endpoints) > 0 {
		pins, err := n.state.TLS.pins()
		if err != nil {
			return err
		}
		cert := n.certificate.Load()
		lease.ExpiresAt = min(lease.ExpiresAt, cert.Leaf.NotAfter.Unix())
		if err := add(service.ProxyV2TLSPrefix+"node", service.ProxyV2TLSType, service.ProxyV2TLS{ProxyV2Lease: lease, Pins: pins}); err != nil {
			return err
		}
	}
	for _, id := range slices.Sorted(maps.Keys(endpoints)) {
		endpoint := endpoints[id]
		endpoint.ProxyV2Lease = lease
		for i := range endpoint.Bindings {
			binding := &endpoint.Bindings[i]
			binding.Addresses = slices.DeleteFunc(slices.Clone(binding.Addresses), func(a service.ProxyV2Address) bool {
				return a.Source == "route-local" && !mesh[a.PortSet]
			})
		}
		endpoint.Bindings = slices.DeleteFunc(endpoint.Bindings, func(b service.ProxyV2Binding) bool { return len(b.Addresses) == 0 })
		if len(endpoint.Bindings) == 0 {
			continue
		}
		if err := add(service.ProxyV2EndpointPrefix+id, service.ProxyV2EndpointType, endpoint); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(n.ctx, setupTimeout)
	defer cancel()
	if err := n.host.Publish(ctx, publication); err != nil {
		return err
	}

	next := n.state
	next.Activated = maps.Clone(next.Activated)
	next.Ports = ports
	for group := range next.Pending {
		next.Activated[group] = now
	}
	next.Pending = nil
	if next.TLS.Next != nil && next.TLS.ActivateAt.IsZero() {
		next.TLS.ActivateAt = now.Add(n.config.TLS.Overlap)
	}
	if err := n.db.saveV2(next); err != nil {
		return err
	}
	n.state = next
	for key, servers := range n.listeners {
		set := ports[key.group]
		if key.port == set.Current.Port || set.Previous != nil && key.port == set.Previous.Port {
			for _, server := range servers {
				server.enabled.Store(true)
			}
		} else {
			delete(n.listeners, key)
			n.retire(servers)
		}
	}
	n.lastPublication = now
	n.lastMesh = mesh
	return nil
}

func sendV2Publication(ctx context.Context, socket string, publication service.ProxyV2Publication) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(publication); err != nil {
		return err
	}
	var result service.ProxyV2PublicationResult
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("publish proxy records: %s", result.Error)
	}
	return nil
}

func (n *v2Node) tick() error {
	now := time.Now()
	n.updateInternalNetworks()
	if len(n.config.PortGroups) > 0 {
		before := n.state.TLS
		if err := n.refreshTLS(now); err != nil {
			return err
		}
		if !reflect.DeepEqual(before, n.state.TLS) {
			n.lastPublication = time.Time{}
		}
	}
	var rotationError error
	if len(n.state.Pending) == 0 {
		rotationError = n.takeRotationRequest()
		for _, name := range slices.Sorted(maps.Keys(n.config.PortGroups)) {
			config := n.config.PortGroups[name]
			if len(n.state.Pending) != 0 {
				break
			}
			if config.RotateInterval > 0 && !now.Before(n.state.Activated[name].Add(config.RotateInterval)) {
				rotationError = errors.Join(rotationError, n.stagePort(name))
			}
		}
	}
	if len(n.state.Pending) != 0 || n.state.TLS.Next != nil && n.state.TLS.ActivateAt.IsZero() ||
		!reflect.DeepEqual(n.lastMesh, n.checkMeshAddresses(n.desiredPorts())) || now.Sub(n.lastPublication) >= time.Minute {
		return errors.Join(rotationError, n.publish())
	}
	return rotationError
}

func (n *v2Node) updateInternalNetworks() {
	view := n.directory.snapshotV2()
	addresses, _ := net.InterfaceAddrs()
	prefixes := make([]netip.Prefix, 0, len(view.MeshPrefixes)+len(addresses))
	add := func(value string) {
		if ip, err := netip.ParsePrefix(value); err == nil {
			prefixes = append(prefixes, ip.Masked())
		}
	}
	for _, prefix := range view.MeshPrefixes {
		add(prefix)
	}
	for _, addr := range addresses {
		add(addr.String())
	}
	n.server.internal.Store(&prefixes)
}

func (n *v2Node) stagePort(group string, requestID ...string) error {
	config := n.config.PortGroups[group]
	if len(config.Range) != 2 {
		return fmt.Errorf("port group %q is not configured for rotation", group)
	}
	current := n.state.Ports[group]
	count := int(config.Range[1]) - int(config.Range[0]) + 1
	start := int(current.Current.Port) - int(config.Range[0])
	var last error
	for offset := 1; offset < count; offset++ {
		port := uint16(int(config.Range[0]) + (start+offset)%count)
		if current.Previous != nil && port == current.Previous.Port {
			continue
		}
		key := v2ListenerKey{group, port}
		listeners, err := n.listen(key)
		if err != nil {
			last = err
			continue
		}
		n.listeners[key] = listeners
		next := n.state
		if len(requestID) != 0 {
			next.LastRotation = requestID[0]
		}
		previous := current.Current
		next.Pending = map[string]service.ProxyV2Ports{group: {Current: service.ProxyV2Port{Generation: previous.Generation + 1, Port: port}, Previous: &previous}}
		if err := n.db.saveV2(next); err != nil {
			delete(n.listeners, key)
			n.retire(listeners)
			return err
		}
		n.state = next
		log.Printf("staged proxy TCP port %d for group %s", port, group)
		return nil
	}
	return fmt.Errorf("no available TCP port in group %s: %w", group, last)
}

func (n *v2Node) refreshTLS(now time.Time) error {
	next := n.state
	tlsState := &next.TLS
	if tlsState.Next != nil && !tlsState.ActivateAt.IsZero() && !now.Before(tlsState.ActivateAt) {
		old := tlsState.Current
		tlsState.Current = *tlsState.Next
		tlsState.Next = nil
		tlsState.ActivateAt = time.Time{}
		tlsState.Retired = &old
		tlsState.RetireAt = now.Add(n.config.TLS.Overlap)
	}
	if tlsState.Retired != nil && !now.Before(tlsState.RetireAt) {
		tlsState.Retired = nil
		tlsState.RetireAt = time.Time{}
	}
	cert, err := tlsState.Current.certificate()
	if err != nil {
		return err
	}
	if now.Add(n.config.TLS.RenewBefore).After(cert.Leaf.NotAfter) {
		material, err := makeV2TLS(now, n.config.TLS.Lifetime, tlsState.Current.Key)
		if err != nil {
			return err
		}
		tlsState.Current = material
		cert, err = material.certificate()
		if err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(next.TLS, n.state.TLS) {
		if err := n.db.saveV2(next); err != nil {
			return err
		}
		n.state = next
	}
	n.certificate.Store(cert)
	return nil
}

func (n *v2Node) takeRotationRequest() error {
	path := filepath.Join(n.config.StateDir, v2RotationFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var request v2RotationRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return err
	}
	if request.ID == "" {
		return errors.New("rotation request needs an ID")
	}
	if request.ID == n.state.LastRotation {
		return os.Remove(path)
	}
	if request.TLS {
		if n.state.TLS.Next != nil || n.state.TLS.Retired != nil {
			return nil
		}
		material, err := makeV2TLS(time.Now(), n.config.TLS.Lifetime, nil)
		if err != nil {
			return err
		}
		next := n.state
		next.LastRotation = request.ID
		next.TLS.Next = &material
		if err := n.db.saveV2(next); err != nil {
			return err
		}
		n.state = next
	} else {
		if len(n.config.PortGroups[request.Group].Range) != 2 {
			return errors.Join(fmt.Errorf("rotation request references unavailable group %q", request.Group), os.Remove(path))
		}
		if err := n.stagePort(request.Group, request.ID); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func rotateV2(args []string) error {
	flags := flag.NewFlagSet("photon-proxy rotate", flag.ContinueOnError)
	path := flags.String("config", "", "unified Photon Proxy v2 YAML configuration")
	group := flags.String("port-group", "", "rotating TCP port group")
	key := flags.Bool("tls", false, "stage a new TLS private key")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *path == "" || (*group == "") == !*key {
		return errors.New("rotate requires -config and either -port-group or -tls")
	}
	config, err := readV2Config(*path)
	if err != nil {
		return err
	}
	return rotateV2Config(config, *group, *key)
}

func rotateV2Config(config v2Config, group string, key bool) error {
	if (group == "") == !key {
		return errors.New("rotate requires either a port group or TLS key rotation")
	}
	if key && len(config.PortGroups) == 0 {
		return errors.New("this node has no TLS listeners")
	}
	if group != "" && len(config.PortGroups[group].Range) != 2 {
		return errors.New("port group is not configured for rotation")
	}
	if err := prepareV2StateDir(config.StateDir); err != nil {
		return err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	return requestV2Rotation(config.StateDir, v2RotationRequest{
		ID: delegationEncoding.EncodeToString(id[:]), Group: group, TLS: key,
	})
}
