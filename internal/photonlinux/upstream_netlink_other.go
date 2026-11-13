//go:build !linux

package photonlinux

import (
	"context"
	"fmt"
)

func withUpstreamRouteIO(context.Context, UpstreamRouteSpec, func(upstreamRouteIO) error) error {
	return fmt.Errorf("upstream route management requires Linux")
}
