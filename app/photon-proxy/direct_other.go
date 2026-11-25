//go:build !linux

package main

import "errors"

func inLinkNamespace[T any](_ string, _ func() (T, error)) (T, error) {
	var zero T
	return zero, errors.New("direct Photon links require Linux")
}
