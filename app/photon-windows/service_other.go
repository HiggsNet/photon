//go:build !windows

package main

import "errors"

func manageService(string, string, string) error {
	return errors.New("SCM service management is only available on Windows")
}
