package observer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type testProvider struct{}

func (testProvider) Status() (any, error)       { return map[string]any{}, nil }
func (testProvider) Zones(string) (any, error)  { return map[string]any{}, nil }
func (testProvider) Peers(string) (any, error)  { return map[string]any{}, nil }
func (testProvider) Links(string) (any, error)  { return map[string]any{}, nil }
func (testProvider) Health(string) (any, error) { return map[string]any{}, nil }
func (testProvider) HealthSeries(string, map[string]string) (any, error) {
	return map[string]any{}, nil
}
func (testProvider) Routes() (any, error) { return map[string]any{}, nil }
func (testProvider) Bird() (any, error)   { return map[string]any{}, nil }

func newTestServer() *Server {
	return NewServer(testProvider{}, Config{Enabled: true})
}

func TestStaticHandler(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if body == "" {
		t.Error("static file response should not be empty")
	}
}

func TestStaticHandlerSPAFallbackContentType(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/overlay/links", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("content type = %q, want text/html; charset=utf-8", ct)
	}
}

func TestStaticHandlerEmbeddedFiles(t *testing.T) {
	cases := []struct {
		path        string
		contentType string
	}{
		{"/style/tokens.css", "text/css; charset=utf-8"},
		{"/style/base.css", "text/css; charset=utf-8"},
		{"/style/pages.css", "text/css; charset=utf-8"},
		{"/src/main.js", "application/javascript; charset=utf-8"},
		{"/src/format.js", "application/javascript; charset=utf-8"},
		{"/src/store.js", "application/javascript; charset=utf-8"},
		{"/src/events.js", "application/javascript; charset=utf-8"},
		{"/src/router.js", "application/javascript; charset=utf-8"},
		{"/src/components/badge.js", "application/javascript; charset=utf-8"},
		{"/src/pages/overview.js", "application/javascript; charset=utf-8"},
		{"/src/pages/health.js", "application/javascript; charset=utf-8"},
		{"/src/pages/health_history.js", "application/javascript; charset=utf-8"},
		{"/src/pages/timeline.js", "application/javascript; charset=utf-8"},
	}
	srv := newTestServer()
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("GET %s: status code = %d, want %d", tc.path, rr.Code, http.StatusOK)
			continue
		}
		if ct := rr.Header().Get("Content-Type"); ct != tc.contentType {
			t.Errorf("GET %s: content type = %q, want %q", tc.path, ct, tc.contentType)
		}
		if rr.Body.Len() == 0 {
			t.Errorf("GET %s: body should not be empty", tc.path)
		}
	}
}

func TestStaticHandlerMethodNotAllowed(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}
