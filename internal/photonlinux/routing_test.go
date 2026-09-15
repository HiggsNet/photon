package photonlinux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestKernelRouteCommandScopesNamespace(t *testing.T) {
	tests := []struct {
		name     string
		spec     transportipsec.NetNSSpec
		family   string
		wantName string
		wantArgs string
	}{
		{name: "host", spec: transportipsec.NetNSSpec{Kind: transportipsec.NetNSHost}, family: "ipv4", wantName: "ip", wantArgs: "-4 route show"},
		{name: "named", spec: transportipsec.NetNSSpec{Kind: transportipsec.NetNSName, Name: "mesh"}, family: "ipv6", wantName: "ip", wantArgs: "netns exec mesh ip -6 route show"},
		{name: "path", spec: transportipsec.NetNSSpec{Kind: transportipsec.NetNSPath, Path: "/run/netns/mesh"}, family: "ipv4", wantName: "nsenter", wantArgs: "--net=/run/netns/mesh ip -4 route show"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, args, err := kernelRouteCommand(tt.spec, tt.family)
			if err != nil {
				t.Fatalf("kernelRouteCommand: %v", err)
			}
			if name != tt.wantName || strings.Join(args, " ") != tt.wantArgs {
				t.Fatalf("command = %s %s, want %s %s", name, strings.Join(args, " "), tt.wantName, tt.wantArgs)
			}
		})
	}
}

func TestWriteBirdConfigCreatesPrivateFile(t *testing.T) {
	dryRun := &transportipsec.DryRunDriver{}
	driver, err := NewLinuxDriver(LinuxDriverOptions{IPsecDriver: dryRun, XFRMDriver: dryRun})
	if err != nil {
		t.Fatalf("NewLinuxDriver: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bird", "bird.conf")
	want := []byte("router id 10.0.0.1;\n")
	if err := driver.WriteBirdConfig(path, want); err != nil {
		t.Fatalf("WriteBirdConfig: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("config = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("config mode = %o, want 600", gotMode)
	}
}
