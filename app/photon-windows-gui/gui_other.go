//go:build !windows

package main

import "errors"

func runDesktop(desktopOptions) error {
	return errors.New("Photon desktop is available only on Windows")
}
