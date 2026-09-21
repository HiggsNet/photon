package observer

import (
	"io/fs"
	"strings"
	"testing"
)

func webSubFSForTest() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil
	}
	return sub
}

func readWebFile(t *testing.T, webFS fs.FS, name string) string {
	t.Helper()
	data, err := fs.ReadFile(webFS, name)
	if err != nil {
		t.Fatalf("read %s error: %v", name, err)
	}
	return string(data)
}

func TestWebSubFS(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	data, err := fs.ReadFile(webFS, "index.html")
	if err != nil {
		t.Fatalf("read index.html error: %v", err)
	}
	if len(data) == 0 {
		t.Error("index.html should not be empty")
	}
}

func TestWebModulesExist(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	for _, name := range []string{
		"style/tokens.css",
		"style/base.css",
		"style/pages.css",
		"src/main.js",
		"src/api.js",
		"src/store.js",
		"src/events.js",
		"src/router.js",
		"src/format.js",
		"src/components/badge.js",
		"src/components/card.js",
		"src/components/table.js",
		"src/components/kv.js",
		"src/components/jsonview.js",
		"src/components/chart.js",
		"src/pages/overview.js",
		"src/pages/gossip.js",
		"src/pages/zones.js",
		"src/pages/overlay.js",
		"src/pages/health.js",
		"src/pages/health_history.js",
		"src/pages/routes.js",
		"src/pages/bird.js",
		"src/pages/timeline.js",
	} {
		if _, err := fs.Stat(webFS, name); err != nil {
			t.Errorf("web module %s missing: %v", name, err)
		}
	}
}

func TestIndexHTMLModuleShell(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	body := readWebFile(t, webFS, "index.html")
	for _, token := range []string{
		`type="module" src="/src/main.js"`,
		`/style/tokens.css`,
		`/style/base.css`,
		`/style/pages.css`,
		`id="connection-status"`,
	} {
		if !strings.Contains(body, token) {
			t.Errorf("index.html missing token %q", token)
		}
	}
}
