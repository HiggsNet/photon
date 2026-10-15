//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
)

func desktopOpenConfig(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("config must be a regular file, not a link")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !os.SameFile(info, opened) {
		file.Close()
		return nil, errors.New("config changed while opening")
	}
	return file, nil
}

func desktopPrepareReplacement(_ string, file *os.File, mode os.FileMode) error {
	return file.Chmod(mode.Perm())
}
func desktopReplaceConfig(temp, path string, exists bool) error {
	if exists {
		if err := os.Rename(temp, path); err != nil {
			return err
		}
	} else if err := os.Link(temp, path); err != nil {
		return err
	}
	dir, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
