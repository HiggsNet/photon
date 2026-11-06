//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
)

func runElevatedFrontend(ctx context.Context, path string, stream io.ReadWriteCloser, stderr io.Writer) int {
	return runFrontendBackend(ctx, path, stream, "", stderr)
}

func runFrontendWorker(_ context.Context, _ []string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "frontend elevation is only available on Windows")
	return 2
}
