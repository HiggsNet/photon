//go:build windows

package photonwindows

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestAutoJoinNativeStateDACLProtectsPersistedIdentity(t *testing.T) {
	assertDACL := func(path string) {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		flags, _, err := sd.Control()
		if err != nil || flags&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("state DACL is not protected", err)
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil || acl.AceCount != 2 {
			t.Fatal("state DACL has unexpected entries", err)
		}
		seen := map[string]bool{}
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, i, &ace); err != nil {
				t.Fatal(err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (!sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
				t.Fatal("state DACL admits another principal")
			}
			seen[sid.String()] = true
		}
		if len(seen) != 2 {
			t.Fatal("state DACL lacks SYSTEM or Administrators")
		}
	}
	// Protect the empty staging file before any Bolt/private-key bytes exist.
	staging := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(staging, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := protectNewStateFile(staging); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(staging)
	if err != nil || info.Size() != 0 {
		t.Fatal("staging file was not empty before protection", err)
	}
	assertDACL(staging)
	config := autoJoinConfig(t)
	state, err := OpenOrInitializeState(config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	assertDACL(config.State.Path)
	// Check actual filesystem authorization with Administrators disabled,
	// rather than inferring denial solely from the descriptor's text.
	restricted := controlRestrictedToken(t)
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	path, err := windows.UTF16PtrFromString(config.State.Path)
	if err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.SetThreadToken(nil, impersonation); err != nil {
		t.Fatal(err)
	}
	handle, openErr := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	revertErr := windows.RevertToSelf()
	if openErr == nil {
		windows.CloseHandle(handle)
		t.Fatal("unprivileged token read persisted private identity")
	}
	if !errors.Is(openErr, windows.ERROR_ACCESS_DENIED) || revertErr != nil {
		t.Fatal(openErr, revertErr)
	}
}
