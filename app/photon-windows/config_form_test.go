package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func richDesktopConfig(t *testing.T, path string) string {
	t.Helper()
	text := desktopTestConfig(filepath.Join(filepath.Dir(path), "separate state", "stable.db"))
	text = strings.Replace(text, "  split_routes: [10.42.0.0/16]", "  split_routes: [10.42.0.0/16, fd42:1234::/48]", 1)
	text = strings.Replace(text, "  allowed_zones: [gateway.]", "  allowed_zones: [gateway., second.gateway., third.gateway.]\n  bootstrap_hints:\n    - peer: gateway.\n      address: gateway.example.net:33434\n    - peer: second.gateway.\n      address: '[2001:db8::1]:33435'\n    - peer: gateway.\n      address: 192.0.2.7:33436", 1)
	return text + "gossip_listen: '[::1]:45678'\nwintun:\n  adapter_name: 'Photon: 实验 #2'\n  mtu: 9000\nlog:\n  level: warn\nreconnect:\n  initial_backoff: 125ms\n  max_backoff: 2m13.25s\n"
}

func TestDesktopConfigFormCompleteRoundTripPreservesAdvancedAndMultipleRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.yaml")
	text := richDesktopConfig(t, path)
	want, err := desktopParseConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	form, err := b.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	if len(form.BootstrapHints) != 3 || len(desktopFormLines(form.AllowedGateways)) != 3 || len(desktopFormLines(form.SplitRoutes)) != 2 {
		t.Fatalf("form lost configured lists: %+v", form)
	}
	if form.GossipListen != "[::1]:45678" || form.AdapterName != "Photon: 实验 #2" || form.MTU != "9000" || form.InitialBackoff != "125ms" || form.MaxBackoff != "2m13.25s" || form.LogLevel != "warn" {
		t.Fatalf("form lost advanced values: %+v", form)
	}
	if err := b.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := desktopParseConfig(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("form/save changed configuration semantics\n got: %#v\nwant: %#v", got, want)
	}
	reloaded, err := b.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded, form) {
		t.Fatalf("form changed after reload\n got: %#v\nwant: %#v", reloaded, form)
	}
	form.MTU, form.LogLevel = "1360", "debug"
	if err := b.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	after, err := b.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, form) {
		t.Fatal("editing selected options lost another advanced value or row")
	}
	if _, err := os.Stat(want.State.Path); !os.IsNotExist(err) {
		t.Fatal("form editor created/opened the state database")
	}
}

func TestDesktopConfigFormMissingDefaultsRequireRealTrustAndDoNotCreateIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "laptop-one.yaml")
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	form, err := b.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	if !form.NewConfig {
		t.Fatal("missing configuration was not identified as a new form")
	}
	if form.RootPublicKey != "" || form.ManagedZone != "" || form.AllowedGateways != "" || form.SplitRoutes != "" || len(form.BootstrapHints) != 0 {
		t.Fatal("new form invented trust, network authority or routes")
	}
	if form.StatePath != filepath.Join(dir, "laptop-one.db") || !filepath.IsAbs(form.StatePath) || form.OverlayID != "main" || form.GossipListen != "0.0.0.0:33434" || form.AdapterName != "Photon Windows" || form.MTU != "1400" || form.LogLevel != "info" || form.InitialBackoff != "1s" || form.MaxBackoff != "1m" {
		t.Fatalf("unexpected defaults: %+v", form)
	}
	if err := b.SaveForm(form); err == nil {
		t.Fatal("empty trust and required fields accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid form created a config file")
	}
	if other := defaultDesktopConfigForm(filepath.Join(dir, "laptop-two.yaml")); other.StatePath == form.StatePath {
		t.Fatal("different instances default to the same database")
	}
	if dbNamed := defaultDesktopConfigForm(filepath.Join(dir, "config.db")); strings.EqualFold(dbNamed.StatePath, filepath.Join(dir, "config.db")) {
		t.Fatal("default database collides with config file")
	}
	form.RootPublicKey, form.ManagedZone = strings.Repeat("01", 32), "laptop.catofes."
	form.AllowedGateways, form.SplitRoutes = "gateway.catofes.", "10.42.0.0/16\r\nfd42::/16"
	form.BootstrapHints = []desktopBootstrapRow{{Peer: "gateway.catofes.", Address: "gateway.example.net:33434"}}
	if err := b.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(form.StatePath); !os.IsNotExist(err) {
		t.Fatal("configuration save initialized a private identity")
	}
	if saved, err := b.LoadForm(); err != nil || saved.NewConfig {
		t.Fatalf("saved configuration still new: %+v, %v", saved, err)
	}
}

func completeFirstRunForm(form *desktopConfigForm) {
	form.RootPublicKey, form.ManagedZone = strings.Repeat("01", 32), "laptop.catofes."
	form.AllowedGateways, form.SplitRoutes = "gateway.catofes.", "10.42.0.0/16"
	form.BootstrapHints = []desktopBootstrapRow{{Peer: "gateway.catofes.", Address: "gateway.example.net:33434"}}
}

func TestDesktopConfigFormFirstRunStatusDoesNotRequireAnotherLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path, ServiceName: "PhotonFirstRun-" + filepath.Base(dir)})
	if err != nil {
		t.Fatal(err)
	}
	form, err := b.LoadForm()
	if err != nil || !form.NewConfig {
		t.Fatalf("first load: %+v, %v", form, err)
	}
	// The GUI always takes a status snapshot after loading and on refresh.
	// An absent/inaccessible SCM service must not invalidate this loaded form.
	for i := 0; i < 2; i++ {
		b.Snapshot(context.Background())
	}
	completeFirstRunForm(&form)
	if err := b.SaveForm(form); err != nil {
		t.Fatalf("first save without another load: %v", err)
	}
	if _, err := os.Stat(form.StatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("saving first configuration created a private identity")
	}
	saved, err := b.LoadForm()
	if err != nil || saved.NewConfig {
		t.Fatalf("saved load: %+v, %v", saved, err)
	}
	if saved.StatePath != form.StatePath || saved.ManagedZone != form.ManagedZone || saved.AllowedGateways != form.AllowedGateways || saved.SplitRoutes != form.SplitRoutes || !reflect.DeepEqual(saved.BootstrapHints, form.BootstrapHints) {
		t.Fatalf("first configuration did not round trip: got %+v, want %+v", saved, form)
	}
}

func TestDesktopConfigFormFirstRunDoesNotOverwriteConcurrentCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	form, err := b.LoadForm()
	if err != nil || !form.NewConfig {
		t.Fatalf("first load: %+v, %v", form, err)
	}
	completeFirstRunForm(&form)
	external := desktopTestConfig(filepath.Join(filepath.Dir(path), "other.db"))
	if err := os.WriteFile(path, []byte(external), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveForm(form); err == nil || !strings.Contains(err.Error(), "created outside") {
		t.Fatalf("concurrent creation was not rejected: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != external {
		t.Fatalf("concurrent configuration changed: %q, %v", data, err)
	}
}

func TestDesktopConfigFormMissingDirectoryReportsPathAndCanRetry(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-created")
	path := filepath.Join(dir, "config.yaml")
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	form, err := b.LoadForm()
	if err != nil || !form.NewConfig {
		t.Fatalf("first load with missing parent: %+v, %v", form, err)
	}
	completeFirstRunForm(&form)
	if err := b.SaveForm(form); !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "create it before saving") {
		t.Fatalf("missing parent did not give actionable error: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed save created missing parent directory")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveForm(form); err != nil {
		t.Fatalf("save after creating parent required another load: %v", err)
	}
}

func TestDesktopConfigFormInvalidFieldsAndExternalChangesLeaveOriginalUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.yaml")
	text := richDesktopConfig(t, path)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := newDesktopBackend(desktopOptions{ConfigPath: path})
	form, err := b.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*desktopConfigForm){
		func(f *desktopConfigForm) { f.RootPublicKey = "" },
		func(f *desktopConfigForm) { f.ManagedZone = "missing-dot" },
		func(f *desktopConfigForm) { f.StatePath = "relative.db" },
		func(f *desktopConfigForm) { f.MTU = "not an integer" },
		func(f *desktopConfigForm) { f.MTU = "1279" },
		func(f *desktopConfigForm) { f.SplitRoutes = "0.0.0.0/0" },
		func(f *desktopConfigForm) { f.AllowedGateways = "" },
		func(f *desktopConfigForm) {
			f.BootstrapHints = []desktopBootstrapRow{{Peer: "unknown.", Address: "host:33434"}}
		},
		func(f *desktopConfigForm) {
			f.BootstrapHints = []desktopBootstrapRow{{Peer: "gateway.", Address: "host"}}
		},
		func(f *desktopConfigForm) { f.GossipListen = "hostname:33434" },
		func(f *desktopConfigForm) { f.LogLevel = "unknown" },
		func(f *desktopConfigForm) { f.InitialBackoff = "-1s" },
		func(f *desktopConfigForm) { f.MaxBackoff = "1ns" },
	} {
		invalid := form
		mutate(&invalid)
		if err := b.SaveForm(invalid); err == nil {
			t.Fatalf("invalid form accepted: %+v", invalid)
		}
		if data, _ := os.ReadFile(path); string(data) != text {
			t.Fatal("invalid form changed original file")
		}
	}
	external := text + "# external edit\n"
	if err := os.WriteFile(path, []byte(external), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveForm(form); err == nil {
		t.Fatal("form silently overwrote external changes")
	}
	if data, _ := os.ReadFile(path); string(data) != external {
		t.Fatal("conflict changed external file")
	}
}

func TestDesktopConfigFormLoadFailureCannotOverwriteBrokenExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.yaml")
	valid := richDesktopConfig(t, path)
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := newDesktopBackend(desktopOptions{ConfigPath: path})
	previous, err := b.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	for _, broken := range []string{"malformed: [\n", valid + "unknown_option: true\n", valid + "---\nschema_version: 1\n"} {
		if err := os.WriteFile(path, []byte(broken), 0600); err != nil {
			t.Fatal(err)
		}
		form, err := b.LoadForm()
		if err == nil || !reflect.DeepEqual(form, desktopConfigForm{}) {
			t.Fatalf("invalid config replaced by defaults: %+v, %v", form, err)
		}
		if err := b.SaveForm(previous); err == nil {
			t.Fatal("failed load permitted old form to overwrite broken file")
		}
		if data, _ := os.ReadFile(path); string(data) != broken {
			t.Fatal("broken original file changed")
		}
	}
}

func TestDesktopConfigFormListsAndEmptyOptionalBootstrap(t *testing.T) {
	form := defaultDesktopConfigForm(filepath.Join(t.TempDir(), "instance.yaml"))
	form.RootPublicKey, form.ManagedZone = strings.Repeat("02", 32), "node.catofes."
	form.SplitRoutes, form.AllowedGateways = "\r\n10.42.0.0/16\r\n\r\n fd42::/16 \n", " gateway.catofes. \r\n\nsecond.catofes.\n"
	form.BootstrapHints = []desktopBootstrapRow{{}}
	text, err := desktopFormText(form)
	if err != nil {
		t.Fatal(err)
	}
	config, err := photonwindows.ParseConfig(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Overlay.SplitRoutes) != 2 || len(config.Gateway.AllowedZones) != 2 || len(config.Gateway.BootstrapHints) != 0 {
		t.Fatal("list conversion changed existing optional-bootstrap contract")
	}
}

func TestDesktopConfigFormGatewayPatternsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.yaml")
	if err := os.WriteFile(path, []byte(richDesktopConfig(t, path)), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	form, err := b.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	for _, patterns := range []string{"*.gateway.\r\ngateway.", "*"} {
		form.AllowedGateways = patterns
		if err := b.SaveForm(form); err != nil {
			t.Fatalf("save %q: %v", patterns, err)
		}
		got, err := b.LoadForm()
		if err != nil {
			t.Fatalf("reload %q: %v", patterns, err)
		}
		if !reflect.DeepEqual(got, form) {
			t.Fatalf("gateway selectors or bootstrap rows changed after save/reload\n got: %#v\nwant: %#v", got, form)
		}
	}
}
