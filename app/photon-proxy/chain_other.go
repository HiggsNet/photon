//go:build !linux

package main

import (
	"errors"
	"syscall"
)

func bindChainDevice(string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		return errors.New("proxy chain device binding is only supported on Linux")
	}
}
