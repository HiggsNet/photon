package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

//go:embed v2_ui.html v2_ui.js v2_ui.css
var v2Web embed.FS

type v2DirectoryEndpoint struct {
	Zone         zone.ZonePath `json:"zone"`
	Endpoint     string        `json:"endpoint"`
	Role         string        `json:"role"`
	Links        []string      `json:"links"`
	Discoverable bool          `json:"discoverable"`
}

type v2CandidateList struct {
	Endpoints []v2DirectoryEndpoint `json:"endpoints"`
	Paths     [][]string            `json:"paths"`
}

type v2ProbeRequest struct {
	Protocol string   `json:"protocol"`
	Target   string   `json:"target"`
	Hops     []string `json:"hops,omitempty"`
}

type v2ProbeResult struct {
	OK        bool   `json:"ok"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Error     string `json:"error,omitempty"`
	FailedHop *int   `json:"failed_hop,omitempty"`
}

func (n *v2Node) startV2Admin(manager *routeManager) error {
	config := n.config.Client.Admin
	var tcp, socket net.Listener
	var err error
	if config.Listen != "" {
		tcp, err = net.Listen("tcp", config.Listen)
		if err != nil {
			return err
		}
	}
	if config.Socket != "" {
		socket, err = listenClientAdmin(config.Socket)
		if err != nil {
			if tcp != nil {
				_ = tcp.Close()
			}
			return err
		}
	}
	listen := ""
	if tcp != nil {
		listen = tcp.Addr().String()
		log.Printf("Photon Proxy management API listening on %s", listen)
	}
	for _, listener := range []net.Listener{tcp, socket} {
		if listener == nil {
			continue
		}
		isTCP := listener == tcp
		server := &http.Server{
			Handler: n.v2AdminHandler(manager, listen, isTCP), ReadHeaderTimeout: 3 * time.Second,
			ReadTimeout: setupTimeout, WriteTimeout: setupTimeout, IdleTimeout: time.Minute, MaxHeaderBytes: 8 << 10,
			BaseContext: func(net.Listener) context.Context { return n.ctx },
		}
		n.workers.Go(func() {
			stop := context.AfterFunc(n.ctx, func() { _ = server.Close() })
			defer stop()
			defer listener.Close()
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				n.report(err)
			}
		})
	}
	return nil
}

func (n *v2Node) v2AdminHandler(manager *routeManager, listen string, isTCP bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", routeAdminHandler(manager))
	mux.HandleFunc("GET /v1/admin", func(w http.ResponseWriter, _ *http.Request) {
		writeRouteJSON(w, http.StatusOK, map[string]string{"listen": listen})
	})
	mux.HandleFunc("GET /v1/candidates", func(w http.ResponseWriter, r *http.Request) {
		protocol := r.URL.Query().Get("protocol")
		if protocol == "" {
			protocol = "tcp"
		}
		target := r.URL.Query().Get("target")
		var destination netip.AddrPort
		if target != "" {
			var err error
			destination, err = netip.ParseAddrPort(target)
			if err != nil || destination.Port() == 0 {
				writeRouteError(w, fmt.Errorf("%w: target needs IP:port", errRouteInvalid))
				return
			}
		}
		if protocol != "tcp" && protocol != "udp" {
			writeRouteError(w, fmt.Errorf("%w: unknown protocol", errRouteInvalid))
			return
		}
		writeRouteJSON(w, http.StatusOK, v2ListCandidates(n.directory.snapshotV2(), protocol, destination, time.Now()))
	})
	handleProbe := func(w http.ResponseWriter, r *http.Request) {
		var request v2ProbeRequest
		if !readRouteJSON(w, r, &request) {
			return
		}
		var opener tunnelOpener
		if name := r.PathValue("name"); name != "" {
			manager.mu.Lock()
			binding := manager.listeners[name]
			if binding != nil {
				opener = binding.client.Load().client
			}
			manager.mu.Unlock()
			if opener == nil {
				writeRouteError(w, errRouteNotFound)
				return
			}
		} else {
			var scope string
			if request.Protocol == "udp" {
				addr, err := netip.ParseAddrPort(request.Target)
				if err != nil {
					writeRouteError(w, fmt.Errorf("%w: UDP probe needs IP:port", errRouteInvalid))
					return
				}
				ip := addr.Addr().Unmap()
				scope = netip.PrefixFrom(ip, ip.BitLen()).String()
			}
			opener = &v2Client{directory: n.directory, pool: n.pool, key: n.key, route: v2RouteString(request.Hops), udp: scope}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		writeRouteJSON(w, http.StatusOK, probeV2(ctx, opener, request.Protocol, request.Target))
	}
	mux.HandleFunc("POST /v1/probe", handleProbe)
	mux.HandleFunc("POST /v1/routes/{name}/probe", handleProbe)
	if n.config.Client.Admin.Web {
		for path, name := range map[string]string{"/ui": "v2_ui.html", "/ui/": "v2_ui.html", "/ui/app.js": "v2_ui.js", "/ui/style.css": "v2_ui.css"} {
			mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != path {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
				w.Header().Set("Referrer-Policy", "no-referrer")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				if strings.HasSuffix(name, ".html") {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
				}
				if strings.HasSuffix(name, ".js") {
					w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
				}
				if strings.HasSuffix(name, ".css") {
					w.Header().Set("Content-Type", "text/css; charset=utf-8")
				}
				data, _ := v2Web.ReadFile(name)
				_, _ = w.Write(data)
			})
		}
	}
	token := sha256.Sum256([]byte(n.config.Client.Admin.Token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			w.Header().Set("Cache-Control", "no-store")
			if isTCP && !n.config.Client.Admin.DisableAuth {
				provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
				digest := sha256.Sum256([]byte(provided))
				if !ok || subtle.ConstantTimeCompare(token[:], digest[:]) != 1 {
					w.Header().Set("WWW-Authenticate", "Bearer")
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			if isTCP && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "cross-site request", http.StatusForbidden)
				return
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if media != "application/json" {
					http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func v2ListCandidates(view service.ProxyDirectory, protocol string, target netip.AddrPort, now time.Time) v2CandidateList {
	list := v2CandidateList{Endpoints: []v2DirectoryEndpoint{}, Paths: [][]string{}}
	if !view.ValidUntil.After(now) {
		return list
	}
	type node struct {
		v2DirectoryEndpoint
		check service.ProxyV2RelayACL
	}
	var relays, exits []node
	for owner, peer := range view.V2 {
		if owner == view.ManagedZone || !validV2ZoneName(owner.String()) {
			continue
		}
		for id, endpoint := range peer.Endpoints {
			candidate := node{v2DirectoryEndpoint: v2DirectoryEndpoint{
				Zone: owner, Endpoint: id, Role: endpoint.Role, Discoverable: true, Links: []string{},
			}}
			for _, link := range []string{"h24", "h26", "h2p"} {
				hop := v2Hop{Zone: owner, Endpoint: id, Link: link}
				binding, ok := resolveV2Endpoint(view, hop, protocol, endpoint.Role, now)
				if !ok {
					continue
				}
				if binding.via == "photon" && len(binding.mesh) == 0 {
					continue
				}
				candidate.Links = append(candidate.Links, link)
			}
			if len(candidate.Links) == 0 {
				continue
			}
			switch endpoint.Role {
			case "relay":
				if endpoint.Relay == nil {
					continue
				}
				acl, err := service.CompileProxyV2Relay(*endpoint.Relay)
				if err != nil || !acl.AllowsSource(view.ManagedZone) {
					continue
				}
				candidate.check = acl
				relays = append(relays, candidate)
			case "exit":
				if endpoint.Exit == nil {
					candidate.Discoverable = false
				} else {
					acl, err := service.CompileProxyV2Exit(*endpoint.Exit)
					if err != nil || !acl.AllowsSource(view.ManagedZone) || target.IsValid() && !acl.AllowsTarget(protocol, target) {
						continue
					}
				}
				exits = append(exits, candidate)
			}
		}
	}
	compare := func(a, b node) int {
		return strings.Compare(a.Zone.String()+"/"+a.Endpoint, b.Zone.String()+"/"+b.Endpoint)
	}
	slices.SortFunc(relays, compare)
	slices.SortFunc(exits, compare)
	for _, candidate := range append(slices.Clone(relays), exits...) {
		list.Endpoints = append(list.Endpoints, candidate.v2DirectoryEndpoint)
	}
	name := func(n node) string {
		value := n.Zone.String()
		if n.Role == "exit" && n.Endpoint != "exit" {
			value += "/" + n.Endpoint
		}
		return value + "@" + n.Links[0]
	}
	// Breadth first so direct paths and one-relay paths precede longer
	// alternatives. Bound the graph walk independently of returned paths.
	type candidatePath []node
	queue := []candidatePath{nil}
	const maxExplored = 1024
	for explored := 0; len(queue) != 0 && len(list.Paths) < 64 && explored < maxExplored; explored++ {
		path := queue[0]
		queue = queue[1:]
		allowed := func(next node) bool {
			if len(path) == 0 {
				return true
			}
			prior := path[len(path)-1]
			return prior.check.Allows(view.ManagedZone, next.Zone) && !slices.ContainsFunc(path, func(hop node) bool { return hop.Zone == next.Zone })
		}
		for _, exit := range exits {
			if len(list.Paths) == 64 {
				break
			}
			if !exit.Discoverable || !allowed(exit) {
				continue
			}
			names := make([]string, 0, len(path)+1)
			for _, hop := range path {
				names = append(names, name(hop))
			}
			list.Paths = append(list.Paths, append(names, name(exit)))
		}
		if len(path) >= chainHopLimit-1 {
			continue
		}
		for _, relay := range relays {
			if len(queue) >= maxExplored {
				break
			}
			if allowed(relay) {
				queue = append(queue, append(slices.Clone(path), relay))
			}
		}
	}
	return list
}

func probeV2(ctx context.Context, opener tunnelOpener, protocol, target string) v2ProbeResult {
	start := time.Now()
	var err error
	switch protocol {
	case "", "tcp":
		if _, err = splitTarget(target); err == nil {
			var stream *tunnelStream
			stream, err = opener.open(ctx, target)
			if err == nil {
				_ = stream.Close()
			}
		}
	case "udp":
		var destination netip.AddrPort
		destination, err = netip.ParseAddrPort(target)
		if err == nil && destination.Port() == 0 {
			err = errors.New("invalid DNS probe port")
		}
		if err == nil {
			err = probeV2UDP(ctx, opener, destination)
		}
	default:
		err = errors.New("protocol must be tcp or udp")
	}
	result := v2ProbeResult{OK: err == nil, ElapsedMS: time.Since(start).Milliseconds()}
	if err != nil {
		var hop *v2HopError
		result.Error = err.Error()
		if errors.As(err, &hop) && hop.index >= 0 {
			result.FailedHop = &hop.index
		}
	}
	return result
}

func probeV2UDP(ctx context.Context, opener tunnelOpener, target netip.AddrPort) error {
	stream, err := opener.open(ctx, trusttunnel.UDPAuthority)
	if err != nil {
		return err
	}
	defer stream.Close()
	// A DNS A query for example.com. The transaction ID is matched on
	// the response as well as the packet's source and destination.
	payload := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := rand.Read(payload[:2]); err != nil {
		return err
	}
	source := netip.MustParseAddrPort("127.0.0.1:49152")
	if err := trusttunnel.WriteRequest(stream, trusttunnel.Datagram{Source: source, Destination: target, Payload: payload}); err != nil {
		return err
	}
	for {
		reply, err := trusttunnel.ReadResponse(stream)
		if err != nil {
			return err
		}
		if reply.Source == target && reply.Destination == source && len(reply.Payload) >= 12 &&
			binary.BigEndian.Uint16(reply.Payload) == binary.BigEndian.Uint16(payload) && reply.Payload[2]&0x80 != 0 {
			return nil
		}
	}
}
