//go:build !windows

package photonwindows

import (
	"os"
	"path/filepath"
)

func protectNewStateFile(path string) error { return os.Chmod(path, 0600) }

func publishNewStateFile(temp, path string) error {
	if err := os.Link(temp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
