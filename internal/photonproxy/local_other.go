//go:build !windows

package photonproxy

import (
	"errors"
	"net"
	"os"
)

func preparePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state_dir must be private, for example mode 0700")
	}
	return nil
}

func verifyPrivateFile(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("proxy state.db must be a private regular file")
	}
	return nil
}

func listenV2AdminSocket(address string) (net.Listener, error) { return listenClientAdmin(address) }

func validateEmbeddedAdminAddress(string) error { return nil }
