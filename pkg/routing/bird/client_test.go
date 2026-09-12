package bird

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleShowStatus = `1000-BIRD 2.15.1
1011-Router ID is 10.64.64.2
 Current server time is 2025-06-13 10:00:00.000
 Last reboot on 2025-06-13 09:00:00.000
 Last reconfiguration on 2025-06-13 09:30:00.000
0000 
`

const sampleShowProtocols = `2002-Name       Proto      Table      State  Since         Info
1002-direct1    Direct     ---        up     2025-06-13
 bfd1       BFD        ---        up     2025-06-13
 kernel1    Kernel     master4    up     2025-06-13
 device1    Device     ---        up     2025-06-13
 babel1     Babel      master4    up     2025-06-13    Established
0000 
`

const sampleShowRoutes = `Table master4:
10.0.0.0/8           unicast [babel1 2025-06-13] * (100)
	via 192.168.1.2 on eth0
192.168.0.0/16       unicast [kernel1 2025-06-13] (240)
	dev eth0
0000 
`

func TestDebugCommands(t *testing.T) {
	tests := []struct {
		view DebugView
		want []string
	}{
		{view: DebugStatus, want: []string{"show status", "show protocols all", "show babel neighbors", "show babel routes", "show babel entries"}},
		{view: DebugInterface, want: []string{"show interfaces"}},
		{view: DebugFilter, want: []string{"show symbols filter"}},
		{view: DebugRoute, want: []string{"show route table all where source = RTS_BABEL all", "show babel routes"}},
	}
	for _, test := range tests {
		got, err := DebugCommands(test.view)
		if err != nil {
			t.Fatalf("DebugCommands(%q): %v", test.view, err)
		}
		if strings.Join(got, "\n") != strings.Join(test.want, "\n") {
			t.Errorf("DebugCommands(%q) = %#v, want %#v", test.view, got, test.want)
		}
	}
	if _, err := DebugCommands("invalid"); err == nil {
		t.Fatal("DebugCommands(invalid) error = nil")
	}
}

const sampleShowInterfaces = `1001-lo up (index=1)
1004-	MultiAccess AdminUp LinkUp Loopback Ignored MTU=65536
1003-	127.0.0.1/8 (Preferred, scope host)
       ::1/128 (scope host)
1001-eth0 up (index=2)
1004-	MultiAccess Broadcast Multicast AdminUp LinkUp MTU=1500
1003-	192.0.2.1/24 (Preferred, scope univ)
       fe80::1/64 (Preferred, scope link)
0000 
`

const sampleShowBabelNeighbors = `1024-babel1:
     IP address                Interface  Metric Routes Hellos Expires Auth  RTT (ms)
1001-fe80::2                   eth0         256      1     16   5.391 No       5.009
     fe80::3                   eth0         512      1     16   5.391 No       5.009
0000 
`

const sampleShowBabelNeighborsV219 = `BIRD 2.19.1 ready.
photon_babel_h2:
IP address                Interface  Metric Routes Hellos Expires Auth  RTT (ms)
fe80::dc29:e1e4:3622:bde5 phx1d556624    100      1     16   5.391 No       5.009
0000`

const sampleShowPhotonRoutes = `Table photon_photon6:
2a0d:2905:1:2::/64   unicast [photon_babel_h2 2026-07-10] * (130/100) [00:00:00:00:f7:24:52:c9]
        via fe80::dc29:e1e4:3622:bde5 on phx1d556624
0000`

// fakeServer is a minimal birdc-style Unix socket server for tests.
type fakeServer struct {
	listener net.Listener
	socket   string
	handler  func(cmd string) string
}

func newFakeServer(t *testing.T, handler func(cmd string) string) *fakeServer {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "bird.ctl")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	s := &fakeServer{
		listener: l,
		socket:   socket,
		handler:  handler,
	}
	go s.serve(t)
	return s
}

func (s *fakeServer) serve(t *testing.T) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(t, conn)
	}
}

func (s *fakeServer) handleConn(t *testing.T, conn net.Conn) {
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "0001 BIRD 2.15.1 ready.\n"); err != nil {
		t.Logf("greeting write: %v", err)
		return
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		response := s.handler(cmd)
		if _, err := fmt.Fprint(conn, response); err != nil {
			return
		}
	}
}

func (s *fakeServer) close() {
	_ = s.listener.Close()
}

func defaultHandler(cmd string) string {
	switch cmd {
	case "show status":
		return sampleShowStatus
	case "show protocols all":
		return sampleShowProtocols
	case "show route all":
		return sampleShowRoutes
	case "show interfaces":
		return sampleShowInterfaces
	case "show babel neighbors":
		return sampleShowBabelNeighbors
	case `configure "/tmp/bird.conf"`:
		return "0002 Configuration OK\n0000 \n"
	case `configure soft "/tmp/bird.conf"`:
		return "0002 Configuration OK\n0000 \n"
	case "reload in babel1":
		return "0002 Reload requested\n0000 \n"
	case "reload out babel1":
		return "0002 Reload requested\n0000 \n"
	case "down":
		return "0002 Shutdown requested\n0000 \n"
	default:
		return "8001 Unknown command\n0000 \n"
	}
}

func TestStatusParsing(t *testing.T) {
	server := newFakeServer(t, defaultHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	state, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if state.Stale {
		t.Fatalf("unexpected stale state, warnings: %v", state.Warnings)
	}

	if state.Status.Version != "2.15.1" {
		t.Errorf("version = %q, want %q", state.Status.Version, "2.15.1")
	}
	if state.Status.RouterID != 0x0A404002 {
		t.Errorf("router id = 0x%x, want 0x%x", state.Status.RouterID, 0x0A404002)
	}
	if state.Status.LastReconfig.IsZero() {
		t.Error("expected LastReconfig to be parsed")
	}

	if len(state.Protocols) != 5 {
		t.Errorf("protocols = %d, want 5", len(state.Protocols))
	}
	foundBabel := false
	for _, p := range state.Protocols {
		if p.Name == "babel1" {
			foundBabel = true
			if p.State != "up" || p.Table != "master4" {
				t.Errorf("unexpected babel1 protocol: %+v", p)
			}
		}
	}
	if !foundBabel {
		t.Error("babel1 protocol not found")
	}

	if len(state.Routes) != 2 {
		t.Errorf("routes = %d, want 2", len(state.Routes))
	}
	var selected *BirdRoute
	for i := range state.Routes {
		if state.Routes[i].Selected {
			selected = &state.Routes[i]
		}
	}
	if selected == nil {
		t.Fatal("no selected route found")
	}
	if selected.Prefix.String() != "10.0.0.0/8" {
		t.Errorf("selected prefix = %q, want 10.0.0.0/8", selected.Prefix)
	}
	if selected.Via.String() != "192.168.1.2" {
		t.Errorf("selected via = %q, want 192.168.1.2", selected.Via)
	}
	if got := state.Routes[1].Iface; got != "eth0" {
		t.Errorf("on-link route interface = %q, want eth0", got)
	}

	if len(state.Interfaces) != 2 {
		t.Errorf("interfaces = %d, want 2", len(state.Interfaces))
	}
	if len(state.Interfaces) == 2 {
		eth0 := state.Interfaces[1]
		if eth0.Index != 2 || eth0.MTU != 1500 || eth0.LinkLocal.String() != "fe80::1" {
			t.Errorf("eth0 = %#v, want index=2 mtu=1500 link-local=fe80::1", eth0)
		}
	}

	if len(state.Neighbors) != 2 {
		t.Errorf("neighbors = %d, want 2", len(state.Neighbors))
	}
	if len(state.Neighbors) > 0 && state.Neighbors[0].Protocol != "babel1" {
		t.Errorf("neighbor protocol = %q, want babel1", state.Neighbors[0].Protocol)
	}
	if len(state.Neighbors) > 0 && state.Neighbors[0].Routes != 1 {
		t.Errorf("neighbor routes = %d, want 1", state.Neighbors[0].Routes)
	}
}

func TestStatusParsesInternalTablesAndBIRD219Neighbors(t *testing.T) {
	server := newFakeServer(t, func(cmd string) string {
		switch cmd {
		case "show status":
			return sampleShowStatus
		case "show protocols all":
			return sampleShowProtocols
		case "show route table photon_photon4 all":
			return "Table photon_photon4:\n0000 \n"
		case "show route table photon_photon6 all":
			return sampleShowPhotonRoutes + " \n"
		case "show interfaces":
			return sampleShowInterfaces
		case "show babel neighbors":
			return sampleShowBabelNeighborsV219 + " \n"
		default:
			return "8001 Unknown command\n0000 \n"
		}
	})
	defer server.close()

	client := NewClientWithRouteTables(server.socket, 5*time.Second, InternalRouteTableNames("photon"))
	state, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if state.Stale {
		t.Fatalf("unexpected stale state, warnings: %v", state.Warnings)
	}
	if len(state.Neighbors) != 1 || state.Neighbors[0].Interface != "phx1d556624" || state.Neighbors[0].Routes != 1 {
		t.Fatalf("neighbors = %#v", state.Neighbors)
	}
	if len(state.Routes) != 1 {
		t.Fatalf("routes = %#v", state.Routes)
	}
	route := state.Routes[0]
	if !route.Selected || route.Iface != "phx1d556624" || route.Metric != 130 {
		t.Fatalf("route = %#v", route)
	}
}

func TestParseRoutesSupportsOnLinkAndNonUnicastDestinations(t *testing.T) {
	routes := parseRoutes(`1007-Table master4:
1007-10.0.0.0/8           blackhole [static1 13:05:41.763] * (200)
1007-10.1.0.0/16          unreachable [static1 13:05:41.763] * (200)
1007-10.2.0.0/16          prohibit [static1 13:05:41.763] * (200)
1007-10.3.0.0/16          unicast [direct1 13:05:41.763] ! (240)
     dev eth0
0000 `)
	if len(routes) != 4 {
		t.Fatalf("routes = %#v, want four routes", routes)
	}
	if routes[3].Iface != "eth0" || routes[3].Selected {
		t.Fatalf("on-link route = %#v, want iface eth0 and unselected", routes[3])
	}
	if routes[0].Source != "static1" {
		t.Fatalf("route source = %q, want static1", routes[0].Source)
	}
}

func TestParseProtocolsParsesSameDaySince(t *testing.T) {
	protocols := parseProtocols(`2002-Name       Proto      Table      State  Since         Info
1002-babel1     Babel      master4    up     13:05:41.762  Established
0000 `)
	if len(protocols) != 1 || protocols[0].Since.IsZero() {
		t.Fatalf("protocols = %#v, want same-day timestamp", protocols)
	}
}

func TestConfigureSuccessAndError(t *testing.T) {
	server := newFakeServer(t, defaultHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)

	if err := client.Configure(context.Background(), "/tmp/bird.conf"); err != nil {
		t.Errorf("Configure succeeded command returned error: %v", err)
	}

	if err := client.ConfigureSoft(context.Background(), "/tmp/bird.conf"); err != nil {
		t.Errorf("ConfigureSoft succeeded command returned error: %v", err)
	}

	err := client.Configure(context.Background(), "/tmp/missing.conf")
	if err == nil {
		t.Fatal("expected error for missing config command")
	}
	if !strings.Contains(err.Error(), "Unknown command") {
		t.Errorf("error message does not mention unknown command: %v", err)
	}
}

func TestConfigureQuotesConfigPath(t *testing.T) {
	const path = `/tmp/photon bird-"next".conf`
	var commands []string
	server := newFakeServer(t, func(cmd string) string {
		commands = append(commands, cmd)
		return "0002 Configuration OK\n0000 \n"
	})
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	if err := client.Configure(context.Background(), path); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if err := client.ConfigureSoft(context.Background(), path); err != nil {
		t.Fatalf("ConfigureSoft: %v", err)
	}

	want := []string{`configure "/tmp/photon bird-\"next\".conf"`, `configure soft "/tmp/photon bird-\"next\".conf"`}
	if len(commands) != len(want) || commands[0] != want[0] || commands[1] != want[1] {
		t.Fatalf("commands = %#v, want %#v", commands, want)
	}
}

func TestShutdown(t *testing.T) {
	server := newFakeServer(t, defaultHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	if err := client.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}
}

func TestRawCommand(t *testing.T) {
	server := newFakeServer(t, defaultHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	out, err := client.Raw(context.Background(), "show route all")
	if err != nil {
		t.Fatalf("Raw returned error: %v", err)
	}
	if !strings.Contains(out, "Table master4:") {
		t.Fatalf("Raw output missing route table:\n%s", out)
	}
}

func TestCommandRejectsUnexpectedGreeting(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "unexpected.ctl")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(conn, "0001 unexpected service\n")
	}()

	_, err = NewClient(socket, time.Second).Raw(context.Background(), "show status")
	if err == nil || !strings.Contains(err.Error(), "unexpected BIRD greeting") {
		t.Fatalf("Raw error = %v, want invalid greeting", err)
	}
}

func TestCommandTimeout(t *testing.T) {
	slowHandler := func(cmd string) string {
		time.Sleep(500 * time.Millisecond)
		return defaultHandler(cmd)
	}
	server := newFakeServer(t, slowHandler)
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Status accumulates per-command failures as stale warnings rather than
	// returning a hard error. Use a single checked command to observe the
	// timeout as an error.
	err := client.Configure(ctx, "/tmp/bird.conf")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "context") {
		t.Errorf("expected timeout-related error, got: %v", err)
	}
}

func TestCommandUsesClientTimeoutWithoutContextDeadline(t *testing.T) {
	slowHandler := func(cmd string) string {
		time.Sleep(500 * time.Millisecond)
		return defaultHandler(cmd)
	}
	server := newFakeServer(t, slowHandler)
	defer server.close()

	client := NewClient(server.socket, 50*time.Millisecond)
	err := client.Configure(context.Background(), "/tmp/bird.conf")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("expected timeout-related error, got: %v", err)
	}
}

func TestRawAcceptsBarePromptTerminator(t *testing.T) {
	server := newFakeServer(t, func(cmd string) string {
		return "1000-BIRD 2.15.1\n0000"
	})
	defer server.close()

	client := NewClient(server.socket, 5*time.Second)
	out, err := client.Raw(context.Background(), "show status")
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}
	if !strings.Contains(out, "BIRD 2.15.1") {
		t.Fatalf("Raw output missing status line: %q", out)
	}
}

func TestReadResponseStopsAtPromptWithoutNewline(t *testing.T) {
	out, err := readResponse(strings.NewReader("1000-BIRD 2.15.1\n0000 "))
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if out != "1000-BIRD 2.15.1\n" {
		t.Fatalf("response = %q", out)
	}
}

func TestReadResponseStopsAtAnyFinalReplyLine(t *testing.T) {
	out, err := readResponse(strings.NewReader("8001 Unknown command\n"))
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if out != "8001 Unknown command\n" {
		t.Fatalf("response = %q", out)
	}
}

func TestReadResponseKeepsContinuationLines(t *testing.T) {
	out, err := readResponse(strings.NewReader("1000-BIRD 2.15.1\n1011-Router ID is 10.64.64.2\n Last reboot today\n0000 \n"))
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	want := "1000-BIRD 2.15.1\n1011-Router ID is 10.64.64.2\n Last reboot today\n"
	if out != want {
		t.Fatalf("response = %q, want %q", out, want)
	}
}

func TestParseStatusDirectly(t *testing.T) {
	status, err := parseStatus(sampleShowStatus)
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if status.Version != "2.15.1" {
		t.Errorf("version = %q, want %q", status.Version, "2.15.1")
	}
	if status.RouterID != 0x0A404002 {
		t.Errorf("router id = 0x%x", status.RouterID)
	}
}

func TestSocketNotFound(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "missing.ctl"), 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	state, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status returned unexpected hard error: %v", err)
	}
	if !state.Stale {
		t.Fatal("expected stale state when socket is missing")
	}
	if len(state.Warnings) == 0 {
		t.Fatal("expected warnings when socket is missing")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
