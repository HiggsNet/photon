package photonproxy

import (
	"fmt"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// The socket retains its namespace after the creating thread returns.
func inLinkNamespace[T any](name string, operation func() (T, error)) (T, error) {
	if name == "" {
		return operation()
	}
	var zero T
	if !filepath.IsAbs(name) {
		name = filepath.Join("/run/netns", name)
	}
	target, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, err
	}
	defer unix.Close(target)

	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		// A locked thread exits if restoring its original namespace fails.
		restore, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		defer unix.Close(restore)
		var from, to unix.Stat_t
		if unix.Fstat(restore, &from) == nil && unix.Fstat(target, &to) == nil && from.Dev == to.Dev && from.Ino == to.Ino {
			runtime.UnlockOSThread()
			value, err := operation()
			done <- result{value: value, err: err}
			return
		}
		if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			done <- result{err: fmt.Errorf("enter link namespace: %w", err)}
			return
		}
		value, err := operation()
		if unix.Setns(restore, unix.CLONE_NEWNET) == nil {
			runtime.UnlockOSThread()
		}
		done <- result{value: value, err: err}
	}()
	out := <-done
	return out.value, out.err
}
