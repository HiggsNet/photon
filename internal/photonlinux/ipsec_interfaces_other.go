//go:build !linux

package photonlinux

import "fmt"

func ReadIPsecInterfaces() ([]IPsecInterface, error) {
	return nil, fmt.Errorf("IPsec interface announcement requires Linux")
}
