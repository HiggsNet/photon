//go:build !windows

package photonwindows

import "context"

func watchPowerResume(ctx context.Context) (<-chan struct{}, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return nil, func() error { return nil }, nil
}
