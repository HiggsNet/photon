package photonlinux

import (
	"os"
	"path/filepath"
	"testing"

	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

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
