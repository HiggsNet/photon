package observer

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

//go:embed all:web
var webFS embed.FS

// Config is the transport-neutral observer server configuration.
type Config struct {
	Enabled            bool
	EventBufferSeconds int
}

// Provider supplies read-only observer snapshots from the owning daemon.
type Provider interface {
	Status() (any, error)
	Zones(filter string) (any, error)
	Peers(filter string) (any, error)
	Links(filter string) (any, error)
	Health(filter string) (any, error)
	HealthSeries(linkID string, query map[string]string) (any, error)
	Routes() (any, error)
	Bird() (any, error)
}

type openMetricsProvider interface {
	OpenMetrics() (string, error)
}

// APIError carries an HTTP status code for provider failures.
type APIError struct {
	StatusCode int
	Err        error
}

func (e APIError) Error() string {
	if e.Err == nil {
		return http.StatusText(e.StatusCode)
	}
	return e.Err.Error()
}

func (e APIError) Unwrap() error { return e.Err }

// Errorf returns an APIError with a formatted message.
func Errorf(statusCode int, format string, args ...any) error {
	return APIError{StatusCode: statusCode, Err: fmt.Errorf(format, args...)}
}

// APIResponse is the unified response wrapper for all REST endpoints.
type APIResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data"`
}

// Server is the read-only HTTP observer. It serves REST snapshot APIs, SSE
// events, and a static UI.
type Server struct {
	provider Provider
	hub      *Hub
}

// NewServer creates a server. It returns nil when the observer is disabled or
// provider is nil.
func NewServer(provider Provider, cfg Config) *Server {
	if !cfg.Enabled || provider == nil {
		return nil
	}
	return &Server{provider: provider, hub: NewHubWithBuffer(cfg.EventBufferSeconds)}
}

// Hub returns the server event hub.
func (s *Server) Hub() *Hub {
	if s == nil {
		return nil
	}
	return s.hub
}

// Handler returns the HTTP handler for the observer.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", s.HandleStatus)
	mux.HandleFunc("/api/v1/zones", s.HandleZones)
	mux.HandleFunc("/api/v1/zones/", s.HandleZones)
	mux.HandleFunc("/api/v1/peers", s.HandlePeers)
	mux.HandleFunc("/api/v1/peers/", s.HandlePeers)
	mux.HandleFunc("/api/v1/links", s.HandleLinks)
	mux.HandleFunc("/api/v1/links/", s.HandleLinks)
	mux.HandleFunc("/api/v1/health", s.HandleHealth)
	mux.HandleFunc("/api/v1/health/", s.HandleHealth)
	mux.HandleFunc("/api/v1/routes", s.HandleRoutes)
	mux.HandleFunc("/api/v1/bird", s.HandleBird)
	mux.HandleFunc("/api/v1/events", s.HandleEvents)
	mux.HandleFunc("/api/v1/events/recent", s.HandleRecentEvents)
	mux.HandleFunc("/metrics", s.HandleMetrics)
	mux.HandleFunc("/", s.HandleStatic)
	return mux
}

// HandleMetrics exposes the optional daemon health OpenMetrics snapshot.
func (s *Server) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	provider, ok := s.provider.(openMetricsProvider)
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := provider.OpenMetrics()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, APIResponse{OK: true, Data: data})
}

func writeAPIError(w http.ResponseWriter, statusCode int, err error) {
	writeJSON(w, statusCode, APIResponse{OK: false, Error: err.Error()})
}

func writeProviderResult(w http.ResponseWriter, data any, err error) {
	if err == nil {
		writeAPIOK(w, data)
		return
	}
	statusCode := http.StatusInternalServerError
	var apiErr APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode != 0 {
		statusCode = apiErr.StatusCode
	}
	writeAPIError(w, statusCode, err)
}

func requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return false
	}
	return true
}

// HandleStatus implements GET /api/v1/status.
func (s *Server) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	data, err := s.provider.Status()
	writeProviderResult(w, data, err)
}

// HandleZones implements GET /api/v1/zones and GET /api/v1/zones/{zone}.
func (s *Server) HandleZones(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	data, err := s.provider.Zones(zoneFilter(r))
	writeProviderResult(w, data, err)
}

// zoneFilter extracts the zone filter from the path. The root zone "." cannot
// be addressed as a path segment — ServeMux cleans "/api/v1/zones/." into a
// redirect to "/api/v1/zones" — so it is accepted via ?zone=. instead.
func zoneFilter(r *http.Request) string {
	filter := pathFilter(r.URL.Path, "/api/v1/zones")
	if filter == "" {
		filter = r.URL.Query().Get("zone")
	}
	return filter
}

// HandlePeers implements GET /api/v1/peers and GET /api/v1/peers/{peer_id}.
func (s *Server) HandlePeers(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	data, err := s.provider.Peers(pathFilter(r.URL.Path, "/api/v1/peers"))
	writeProviderResult(w, data, err)
}

// HandleLinks implements GET /api/v1/links and GET /api/v1/links/{link_id}.
func (s *Server) HandleLinks(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	data, err := s.provider.Links(pathFilter(r.URL.Path, "/api/v1/links"))
	writeProviderResult(w, data, err)
}

// HandleHealth implements GET /api/v1/health, GET /api/v1/health/{link_id},
// and GET /api/v1/health/{link_id}/series.
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	linkFilter := pathFilter(r.URL.Path, "/api/v1/health")
	if before, ok := strings.CutSuffix(linkFilter, "/series"); ok {
		linkID := before
		linkID = strings.TrimSuffix(linkID, "/")
		data, err := s.provider.HealthSeries(linkID, queryMap(r))
		writeProviderResult(w, data, err)
		return
	}
	data, err := s.provider.Health(linkFilter)
	writeProviderResult(w, data, err)
}

// HandleRoutes implements GET /api/v1/routes.
func (s *Server) HandleRoutes(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	data, err := s.provider.Routes()
	writeProviderResult(w, data, err)
}

// HandleBird implements GET /api/v1/bird.
func (s *Server) HandleBird(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	data, err := s.provider.Bird()
	writeProviderResult(w, data, err)
}

// HandleEvents implements GET /api/v1/events (SSE).
func (s *Server) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, fmt.Errorf("streaming not supported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	connected, _ := json.Marshal(Event{Type: "connected", Payload: map[string]any{"client_id": "sse"}})
	fmt.Fprintf(w, "event: connected\ndata: %s\n\n", connected)
	flusher.Flush()
	ch, unsubscribe := s.hub.Subscribe()
	defer unsubscribe()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()
		}
	}
}

// HandleRecentEvents implements GET /api/v1/events/recent. It returns the
// hub replay buffer (empty list when event buffering is disabled).
func (s *Server) HandleRecentEvents(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	writeAPIOK(w, map[string]any{"events": s.hub.Recent()})
}

// HandleStatic serves the embedded static UI files.
func (s *Server) HandleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeAPIError(w, http.StatusNotFound, fmt.Errorf("not found"))
		return
	}
	cleanPath := strings.TrimPrefix(r.URL.Path, "/")
	if cleanPath == "" {
		cleanPath = "index.html"
	}
	servedPath := cleanPath
	data, err := webFS.ReadFile("web/" + cleanPath)
	if err != nil {
		data, err = webFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		servedPath = "index.html"
	}
	contentType := "application/octet-stream"
	switch {
	case strings.HasSuffix(servedPath, ".html"):
		contentType = "text/html; charset=utf-8"
	case strings.HasSuffix(servedPath, ".css"):
		contentType = "text/css; charset=utf-8"
	case strings.HasSuffix(servedPath, ".js"):
		contentType = "application/javascript; charset=utf-8"
	case strings.HasSuffix(servedPath, ".json"):
		contentType = "application/json; charset=utf-8"
	case strings.HasSuffix(servedPath, ".svg"):
		contentType = "image/svg+xml"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func pathFilter(path string, prefix string) string {
	filter := strings.TrimPrefix(path, prefix)
	filter = strings.TrimPrefix(filter, "/")
	return strings.TrimSuffix(filter, "/")
}

func queryMap(r *http.Request) map[string]string {
	out := map[string]string{}
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			out[key] = values[0]
		}
	}
	return out
}

// DefaultHTTPServer returns an HTTP server configured with observer defaults.
func DefaultHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}
