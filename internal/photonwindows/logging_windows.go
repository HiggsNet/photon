package photonwindows

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
)

const eventSourceOwner = "photon-windows-event-source-v1"
const eventSourceParent = `SYSTEM\CurrentControlSet\Services\EventLog\Application`

func validEventSourceName(name string) bool {
	return name != "" && len(name) <= 128 && !strings.ContainsAny(name, `\/`+"\x00")
}

// InstallEventSource refuses an existing source, including one from an old
// installation. The corresponding SCM installer rolls back its new service if
// source registration fails; it cannot adopt another application's log source.
func InstallEventSource(name string) (result error) {
	if !validEventSourceName(name) {
		return errors.New("invalid Event Log source name")
	}
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, eventSourceParent, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer parent.Close()
	key, exists, err := registry.CreateKey(parent, name, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if exists {
		return errors.New("Event Log source already exists")
	}
	defer func() {
		if result != nil {
			_ = registry.DeleteKey(parent, name)
		}
	}()
	if err := key.SetStringValue("PhotonWindowsOwner", eventSourceOwner); err != nil {
		return err
	}
	if err := key.SetDWordValue("CustomSource", 1); err != nil {
		return err
	}
	if err := key.SetExpandStringValue("EventMessageFile", `%SystemRoot%\System32\EventCreate.exe`); err != nil {
		return err
	}
	return key.SetDWordValue("TypesSupported", eventlog.Info|eventlog.Warning|eventlog.Error)
}

func RemoveEventSource(name string) error {
	if !validEventSourceName(name) {
		return errors.New("invalid Event Log source name")
	}
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, eventSourceParent, registry.SET_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return err
	}
	defer parent.Close()
	key, err := registry.OpenKey(parent, name, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	owner, _, err := key.GetStringValue("PhotonWindowsOwner")
	key.Close()
	if err != nil || owner != eventSourceOwner {
		return errors.New("refusing to remove an unowned Event Log source")
	}
	return registry.DeleteKey(parent, name)
}

type windowsRuntimeEventSink struct{ *eventlog.Log }

func openRuntimeEventSink(name string) (runtimeEventSink, error) {
	if !validEventSourceName(name) {
		return nil, errors.New("invalid Event Log source name")
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, eventSourceParent+`\`+name, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	owner, _, err := key.GetStringValue("PhotonWindowsOwner")
	key.Close()
	if err != nil || owner != eventSourceOwner {
		return nil, fmt.Errorf("Event Log source is not registered for Photon Windows")
	}
	log, err := eventlog.Open(name)
	if err != nil {
		return nil, err
	}
	return &windowsRuntimeEventSink{log}, nil
}
func (s *windowsRuntimeEventSink) Report(level slog.Level, id uint32, message string) error {
	if level >= slog.LevelError {
		return s.Error(id, message)
	}
	if level >= slog.LevelWarn {
		return s.Warning(id, message)
	}
	return s.Info(id, message)
}
