package photonproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	errRouteInvalid  = errors.New("invalid route")
	errRouteConflict = errors.New("route conflict")
	errRouteNotFound = errors.New("route not found")
	routeBucket      = []byte("photon-proxy")
	routeKey         = []byte("routes-v1")
)

type routeState struct{ *bolt.DB }

func openRouteState(path string, seed map[string]clientRoute) (*routeState, map[string]clientRoute, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, nil, fmt.Errorf("open route_state: %w", err)
	}
	routes := seed
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(routeBucket)
		if bucket == nil || bucket.Get(routeKey) == nil {
			return nil
		}
		routes = nil
		return json.Unmarshal(bucket.Get(routeKey), &routes)
	})
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("read route_state: %w", err)
	}
	return &routeState{db}, routes, nil
}

func (s *routeState) save(routes map[string]clientRoute) error {
	if s == nil {
		return nil
	}
	data, err := json.Marshal(routes)
	if err != nil {
		return err
	}
	return s.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(routeBucket)
		if err != nil {
			return err
		}
		return bucket.Put(routeKey, data)
	})
}

type listeningRoute struct {
	listener net.Listener
	client   atomic.Pointer[routeOpener]
}

type routeOpener struct{ client tunnelOpener }

type routeInfo struct {
	Name string `json:"name"`
	clientRoute
}

type routeManager struct {
	ctx           context.Context
	cancel        context.CancelFunc
	state         *routeState
	newClient     func(clientEntry) tunnelOpener
	prepare       func(string, clientRoute, bool) (clientEntry, error)
	allowSource   func(netip.Addr) bool
	defaultListen string
	errors        chan error
	workers       sync.WaitGroup

	mu        sync.Mutex
	routes    map[string]clientRoute
	listeners map[string]*listeningRoute
}

func newRouteManager[T tunnelOpener](ctx context.Context, state *routeState, newClient func(clientEntry) T) *routeManager {
	ctx, cancel := context.WithCancel(ctx)
	return &routeManager{
		ctx: ctx, cancel: cancel, state: state, newClient: func(entry clientEntry) tunnelOpener { return newClient(entry) }, errors: make(chan error, 1),
		prepare: prepareClientEntry, defaultListen: "127.0.0.1:0",
		routes: make(map[string]clientRoute), listeners: make(map[string]*listeningRoute),
	}
}

// Bind all startup listeners before accepting any requests or persisting the
// initial routes. A port conflict leaves the stored configuration intact.
func (m *routeManager) start(routes map[string]clientRoute, entries []clientEntry) error {
	for _, entry := range entries {
		listener, err := listenSOCKSRoute(entry.listen)
		if err != nil {
			m.closeListeners()
			return fmt.Errorf("route %q: %w", entry.name, err)
		}
		route := routes[entry.name]
		route.Listen = listener.Addr().String()
		m.routes[entry.name] = route
		binding := &listeningRoute{listener: listener}
		binding.client.Store(&routeOpener{m.newClient(entry)})
		m.listeners[entry.name] = binding
	}
	if err := m.state.save(m.routes); err != nil {
		m.closeListeners()
		return fmt.Errorf("persist initial routes: %w", err)
	}
	for _, entry := range entries {
		m.serve(entry.name, m.listeners[entry.name])
	}
	return nil
}

func (m *routeManager) serve(name string, binding *listeningRoute) {
	log.Printf("SOCKS5 route %q listening on %s", name, binding.listener.Addr())
	m.workers.Go(func() {
		err := serveRestrictedSOCKSListener(m.ctx, binding.listener, func() tunnelOpener { return binding.client.Load().client }, m.allowSource)
		if err != nil {
			select {
			case m.errors <- fmt.Errorf("route %q: %w", name, err):
			default:
			}
		}
	})
}

func (m *routeManager) closeListeners() {
	for _, binding := range m.listeners {
		_ = binding.listener.Close()
	}
}

func (m *routeManager) close() {
	m.cancel()
	m.mu.Lock()
	m.closeListeners()
	m.mu.Unlock()
	m.workers.Wait()
}

func (m *routeManager) list() []routeInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	routes := make([]routeInfo, 0, len(m.routes))
	for _, name := range slices.Sorted(maps.Keys(m.routes)) {
		routes = append(routes, routeInfo{Name: name, clientRoute: m.routes[name]})
	}
	return routes
}

func (m *routeManager) create(name string, route clientRoute) (routeInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctx.Err(); err != nil {
		return routeInfo{}, err
	}
	if _, exists := m.routes[name]; exists {
		return routeInfo{}, fmt.Errorf("%w: %q already exists", errRouteConflict, name)
	}
	if route.Listen == "" {
		route.Listen = m.defaultListen
	}
	entry, err := m.prepare(name, route, true)
	if err != nil {
		return routeInfo{}, fmt.Errorf("%w: %w", errRouteInvalid, err)
	}
	listener, err := listenSOCKSRoute(entry.listen)
	if err != nil {
		return routeInfo{}, fmt.Errorf("%w: %w", errRouteConflict, err)
	}
	route.Listen = listener.Addr().String()
	if err := m.set(name, route); err != nil {
		_ = listener.Close()
		return routeInfo{}, err
	}
	binding := &listeningRoute{listener: listener}
	binding.client.Store(&routeOpener{m.newClient(entry)})
	m.listeners[name] = binding
	m.serve(name, binding)
	return routeInfo{Name: name, clientRoute: route}, nil
}

func listenSOCKSRoute(address netip.AddrPort) (net.Listener, error) {
	network := "tcp"
	if address.Addr().Is4() {
		// The generic TCP listener may turn 0.0.0.0 into a dual-stack socket.
		network = "tcp4"
	}
	return net.Listen(network, address.String())
}

func (m *routeManager) replace(name string, route clientRoute) (routeInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctx.Err(); err != nil {
		return routeInfo{}, err
	}
	previous, exists := m.routes[name]
	if !exists {
		return routeInfo{}, errRouteNotFound
	}
	if route.Listen != "" && route.Listen != previous.Listen {
		return routeInfo{}, fmt.Errorf("%w: replacement must keep listen address %s", errRouteInvalid, previous.Listen)
	}
	route.Listen = previous.Listen
	entry, err := m.prepare(name, route, false)
	if err != nil {
		return routeInfo{}, fmt.Errorf("%w: %w", errRouteInvalid, err)
	}
	if err := m.set(name, route); err != nil {
		return routeInfo{}, err
	}
	m.listeners[name].client.Store(&routeOpener{m.newClient(entry)})
	return routeInfo{Name: name, clientRoute: route}, nil
}

func (m *routeManager) remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctx.Err(); err != nil {
		return err
	}
	binding, exists := m.listeners[name]
	if !exists {
		return errRouteNotFound
	}
	next := maps.Clone(m.routes)
	delete(next, name)
	if err := m.state.save(next); err != nil {
		return fmt.Errorf("persist routes: %w", err)
	}
	m.routes = next
	delete(m.listeners, name)
	// Closing the listener stops new connections. Accepted connections
	// retain their route and drain until client or process shutdown.
	_ = binding.listener.Close()
	return nil
}

func (m *routeManager) set(name string, route clientRoute) error {
	next := maps.Clone(m.routes)
	next[name] = route
	if err := m.state.save(next); err != nil {
		return fmt.Errorf("persist routes: %w", err)
	}
	m.routes = next
	return nil
}
