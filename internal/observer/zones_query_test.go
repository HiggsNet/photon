package observer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type zoneFilterCapturingProvider struct {
	testProvider
	got string
}

func (p *zoneFilterCapturingProvider) Zones(filter string) (any, error) {
	p.got = filter
	return map[string]any{}, nil
}

// The root zone "." cannot be addressed as a URL path segment (ServeMux
// cleans "/api/v1/zones/." into a redirect), so the UI fetches it via the
// ?zone=. query form. The query filter must reach the provider unchanged.
func TestZonesQueryFilterReachesProvider(t *testing.T) {
	provider := &zoneFilterCapturingProvider{}
	srv := NewServer(provider, Config{Enabled: true})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones?zone=.", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if provider.got != "." {
		t.Fatalf("provider filter = %q, want %q", provider.got, ".")
	}

	// Plain list requests keep an empty filter.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if provider.got != "" {
		t.Fatalf("provider filter = %q, want empty for list request", provider.got)
	}
}
