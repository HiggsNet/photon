//go:build !linux

package ipsec

import (
	"context"
	"errors"
)

func inspectPlatformLinks(context.Context, NetNSSpec) ([]observedInterface, error) {
	return nil, errors.New("XFRM netlink inspection requires Linux")
}

func mutatePlatformLink(context.Context, NetNSSpec, string, xfrmMutation) (bool, error) {
	return false, errors.New("XFRM netlink mutations require Linux")
}

func listPlatformNetNS() (map[string]bool, error) {
	return nil, errors.New("named network namespaces require Linux")
}

func probePlatformNetNS(string) (bool, error) {
	return false, errors.New("named network namespaces require Linux")
}

func inXFRMNetNS(NetNSSpec, func() error) error {
	return errors.New("network namespace switching requires Linux")
}
