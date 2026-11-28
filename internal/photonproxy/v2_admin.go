package photonproxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
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

type v2EndpointDirectory struct {
	Origin zone.ZonePath         `json:"origin"`
	Ready  bool                  `json:"ready"`
	Relays []v2DirectoryEndpoint `json:"relays"`
	Exits  []v2DirectoryEndpoint `json:"exits"`
}

type v2DirectoryNode struct {
	v2DirectoryEndpoint
	check service.ProxyV2RelayACL
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
		socket, err = listenV2AdminSocket(config.Socket)
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
		writeRouteJSON(w, http.StatusOK, map[string]any{
			"listen": listen, "socks5_default_listen": manager.defaultListen,
			"socks5_allowed_sources": n.config.Client.AllowedSources,
		})
	})
	mux.HandleFunc("GET /v1/endpoints", func(w http.ResponseWriter, _ *http.Request) {
		writeRouteJSON(w, http.StatusOK, v2ListEndpoints(n.directory.snapshotV2(), time.Now()))
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
		name := r.PathValue("name")
		timeout, err := request.timeout(name != "")
		if err != nil {
			writeRouteError(w, fmt.Errorf("%w: %v", errRouteInvalid, err))
			return
		}
		if name != "" {
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
		if request.Kind == "download" {
			// Extend the normal admin write deadline for a slow transfer.
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout + 2*time.Second))
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		writeRouteJSON(w, http.StatusOK, probeV2(ctx, opener, request))
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
				w.Header().Set("Cache-Control", "no-cache")
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

func v2ListEndpoints(view service.ProxyDirectory, now time.Time) v2EndpointDirectory {
	list := v2EndpointDirectory{
		Origin: view.ManagedZone,
		Ready:  view.ValidUntil.After(now),
		Relays: []v2DirectoryEndpoint{},
		Exits:  []v2DirectoryEndpoint{},
	}
	relays, exits := v2DirectoryNodes(view, "", netip.AddrPort{}, now)
	for _, relay := range relays {
		list.Relays = append(list.Relays, relay.v2DirectoryEndpoint)
	}
	for _, exit := range exits {
		list.Exits = append(list.Exits, exit.v2DirectoryEndpoint)
	}
	return list
}

func v2DirectoryNodes(view service.ProxyDirectory, protocol string, target netip.AddrPort, now time.Time) (relays, exits []v2DirectoryNode) {
	if !view.ValidUntil.After(now) {
		return nil, nil
	}
	protocols := []string{protocol}
	if protocol == "" {
		protocols = []string{"tcp", "udp"}
	}
	for owner, peer := range view.V2 {
		if owner == view.ManagedZone || !validV2ZoneName(owner.String()) {
			continue
		}
		for id, endpoint := range peer.Endpoints {
			candidate := v2DirectoryNode{v2DirectoryEndpoint: v2DirectoryEndpoint{
				Zone: owner, Endpoint: id, Role: endpoint.Role, Discoverable: true, Links: []string{},
			}}
			for _, link := range []string{"h24", "h26", "h2p", "h2l4", "h2l6"} {
				hop := v2Hop{Zone: owner, Endpoint: id, Link: link}
				for _, allowedProtocol := range protocols {
					binding, ok := resolveV2Endpoint(view, hop, allowedProtocol, endpoint.Role, now)
					if ok && (binding.via != "photon" || len(binding.mesh) != 0) {
						candidate.Links = append(candidate.Links, link)
						break
					}
				}
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
	compare := func(a, b v2DirectoryNode) int {
		return strings.Compare(a.Zone.String()+"/"+a.Endpoint, b.Zone.String()+"/"+b.Endpoint)
	}
	slices.SortFunc(relays, compare)
	slices.SortFunc(exits, compare)
	return relays, exits
}

func v2ListCandidates(view service.ProxyDirectory, protocol string, target netip.AddrPort, now time.Time) v2CandidateList {
	list := v2CandidateList{Endpoints: []v2DirectoryEndpoint{}, Paths: [][]string{}}
	relays, exits := v2DirectoryNodes(view, protocol, target, now)
	for _, candidate := range append(slices.Clone(relays), exits...) {
		list.Endpoints = append(list.Endpoints, candidate.v2DirectoryEndpoint)
	}
	name := func(n v2DirectoryNode) string {
		value := n.Zone.String()
		if n.Role == "exit" && n.Endpoint != "exit" {
			value += "/" + n.Endpoint
		}
		return value + "@" + n.Links[0]
	}
	// Breadth first so direct paths and one-relay paths precede longer
	// alternatives. Bound the graph walk independently of returned paths.
	type candidatePath []v2DirectoryNode
	queue := []candidatePath{nil}
	const maxExplored = 1024
	for explored := 0; len(queue) != 0 && len(list.Paths) < 64 && explored < maxExplored; explored++ {
		path := queue[0]
		queue = queue[1:]
		allowed := func(next v2DirectoryNode) bool {
			if len(path) == 0 {
				return true
			}
			prior := path[len(path)-1]
			return prior.check.Allows(view.ManagedZone, next.Zone) && !slices.ContainsFunc(path, func(hop v2DirectoryNode) bool { return hop.Zone == next.Zone })
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
