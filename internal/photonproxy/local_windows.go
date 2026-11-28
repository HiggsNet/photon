package photonproxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func privateSDDL(flags, access string) (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("D:P(A;%[1]s;%[2]s;;;SY)(A;%[1]s;%[2]s;;;BA)(A;%[1]s;%[2]s;;;%[3]s)", flags, access, user.User.Sid), nil
}

func preparePrivateDirectory(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	sddl, err := privateSDDL("OICI", "FA")
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(name, &attrs)
	runtime.KeepAlive(sd)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("proxy state_dir must be a private directory")
	}
	return verifyPrivateFile(path, info)
}

func verifyPrivateFile(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return errors.New("proxy state must be owned by the daemon account or a Windows administrator")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("proxy state requires a private Windows DACL")
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return errors.New("proxy state DACL may grant access only to the daemon account, Administrators and SYSTEM")
		}
	}
	return nil
}

func listenV2AdminSocket(address string) (net.Listener, error) {
	if err := validateEmbeddedAdminAddress(address); err != nil {
		return nil, err
	}
	sddl, err := privateSDDL("", "GA")
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(address, &winio.PipeConfig{SecurityDescriptor: sddl})
}

func validateEmbeddedAdminAddress(address string) error {
	const prefix = `\\.\pipe\`
	if address != "" && (!strings.HasPrefix(strings.ToLower(address), prefix) || len(address) == len(prefix)) {
		return errors.New(`client.admin.socket must use a local Windows named pipe (\\.\pipe\name)`)
	}
	return nil
}
