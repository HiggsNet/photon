//go:build windows

package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestDesktopNativeMihomoPanel(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_GUI_NATIVE") != "1" || os.Getenv("PHOTON_TEST_MIHOMO") == "" {
		t.Skip("requires the interactive Windows desktop and mihomo.exe beside the test executable")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	config := filepath.Join(t.TempDir(), "photon.yaml")
	template := strings.TrimSuffix(config, ".yaml") + ".proxy.yaml"
	if err := os.WriteFile(template, []byte(`
proxy-groups:
  - {name: Manual, type: select, proxies: [REJECT, DIRECT]}
rules:
  - MATCH,Manual
`), 0600); err != nil {
		t.Fatal(err)
	}
	backend, err := newDesktopBackend(desktopOptions{ConfigPath: config})
	if err != nil {
		t.Fatal(err)
	}
	w, err := newDesktopWindow(backend)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.dispose(); err != nil {
			t.Error(err)
		}
		var message guiMessage
		guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x12, 0x12, 1)
	}()

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "native-proxy-direct")
	}))
	defer origin.Close()
	port, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := port.Addr().(*net.TCPAddr)
	port.Close()
	guiSendMessage.Call(w.hwnd, guiWMCommand, guiProxyOpenID, w.controls[guiProxyOpenID])
	if w.proxy == nil {
		t.Fatal("proxy command did not create its native window")
	}
	shown, _, _ := guiUser32.NewProc("IsWindowVisible").Call(w.proxy.hwnd)
	if shown == 0 {
		t.Fatal("proxy window is not visible on the interactive desktop")
	}
	await := func() {
		t.Helper()
		select {
		case result := <-w.proxy.results:
			w.applyProxyResult(result)
			if result.err != nil {
				t.Fatal(result.err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("proxy operation did not finish")
		}
	}
	click := func(id int) {
		guiSendMessage.Call(w.proxy.hwnd, guiWMCommand, uintptr(id), w.controls[id])
	}
	await()
	w.setText(w.controls[guiProxyPortID], strconv.Itoa(address.Port))
	click(guiProxyToggleID)
	await()
	if !w.proxy.status.Running || w.proxy.status.PhotonOnline {
		t.Fatalf("unexpected proxy status without Photon: %+v", w.proxy.status)
	}
	group := slices.Index(w.proxy.groupNames, "Manual")
	if group < 0 {
		t.Fatal("imported template's policy group did not appear")
	}
	guiSendMessage.Call(w.controls[guiProxyGroupsID], 0x0186, uintptr(group), 0)
	guiSendMessage.Call(w.proxy.hwnd, guiWMCommand, guiProxyGroupsID|1<<16, w.controls[guiProxyGroupsID])
	choice := slices.Index(w.proxy.choices, "DIRECT")
	if choice < 0 {
		t.Fatal("DIRECT outlet did not appear")
	}
	guiSendMessage.Call(w.controls[guiProxyChoicesID], 0x0186, uintptr(choice), 0)
	click(guiProxySelectID)
	await()
	proxy := &url.URL{Scheme: "http", Host: address.String()}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(content) != "native-proxy-direct" {
		t.Fatalf("actual HTTP proxy failed: %v %s %q", err, response.Status, content)
	}
	guiSendMessage.Call(w.proxy.hwnd, guiWMClose, 0, 0)
	shown, _, _ = guiUser32.NewProc("IsWindowVisible").Call(w.proxy.hwnd)
	if shown != 0 {
		t.Fatal("proxy window did not hide")
	}
	status, err := w.proxy.core.Status(t.Context())
	if err != nil || !status.Running {
		t.Fatalf("hiding the proxy window stopped the core: %+v, %v", status, err)
	}
	click(guiProxyToggleID)
	await()
	if w.proxy.status.Running {
		t.Fatal("proxy core still running after stop")
	}
	reopened, err := net.Listen("tcp4", address.String())
	if err != nil {
		t.Fatalf("stopped proxy retained its port: %v", err)
	}
	reopened.Close()
}
