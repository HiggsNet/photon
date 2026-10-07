//go:build !windows

package photonwindows

import "errors"

func openRuntimeEventSink(string) (runtimeEventSink, error) {
	return nil, errors.New("Windows Event Log is unavailable on this platform")
}
func InstallEventSource(string) error {
	return errors.New("Windows Event Log is unavailable on this platform")
}
func RemoveEventSource(string) error {
	return errors.New("Windows Event Log is unavailable on this platform")
}
