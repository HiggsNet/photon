//go:build linux

package photonopenwrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"
)

const serviceActionName = "photon-action"
const serviceActionOwner = "photon-openwrt:service-action:v1"
const serviceActionQuery = `{"name":"photon-action","verbose":true}`

// A nil Running means that procd state/ownership could not be verified. An
// absent job has Running=false and no action/exit code. A failed finished job
// retains its exit code and may be retried; submission never means completion.
type serviceActionInfo struct {
	Running  *bool  `json:"running"`
	Action   string `json:"action"`
	ExitCode *int   `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

func (h *Handler) readServiceAction(ctx context.Context) (serviceActionInfo, error) {
	data, err := h.options.Run(ctx, "ubus", "call", "service", "list", serviceActionQuery)
	if err != nil {
		return serviceActionInfo{}, fmt.Errorf("procd service action state unavailable: %w", err)
	}
	var services map[string]struct {
		Data      map[string]string `json:"data"`
		Autostart *bool             `json:"autostart"`
		Instances map[string]struct {
			Running       *bool             `json:"running"`
			Command       []string          `json:"command"`
			Data          map[string]string `json:"data"`
			ExitCode      *int              `json:"exit_code"`
			Respawn       json.RawMessage   `json:"respawn"`
			RespawnPolicy json.RawMessage   `json:"respawn_policy"`
			Env           json.RawMessage   `json:"env"`
			Errors        []string          `json:"errors"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(data, &services); err != nil || services == nil {
		return serviceActionInfo{}, errors.New("invalid procd service action response")
	}
	stopped := false
	if len(services) == 0 {
		return serviceActionInfo{Running: &stopped}, nil
	}
	service, exists := services[serviceActionName]
	if !exists || len(services) != 1 || len(service.Data) != 1 || service.Data["owner"] != serviceActionOwner || len(service.Instances) != 1 || service.Autostart != nil && !*service.Autostart {
		return serviceActionInfo{}, errors.New("procd photon-action service name is occupied by a foreign task")
	}
	instance, exists := service.Instances["main"]
	if !exists || instance.Running == nil || len(instance.Command) != 2 || instance.Command[0] != h.options.InitPath ||
		(instance.Command[1] != "stop" && instance.Command[1] != "restart") || len(instance.Data) != 2 || instance.Data["owner"] != serviceActionOwner ||
		instance.Data["action"] != instance.Command[1] || len(instance.Respawn) != 0 || len(instance.RespawnPolicy) != 0 || len(instance.Env) != 0 {
		return serviceActionInfo{}, errors.New("procd photon-action instance does not match its owned fixed command")
	}
	info := serviceActionInfo{Running: instance.Running, Action: instance.Command[1]}
	if !*instance.Running {
		info.ExitCode = instance.ExitCode
		if info.ExitCode == nil {
			return serviceActionInfo{}, errors.New("procd finished action has no exit code")
		}
		if *info.ExitCode != 0 {
			info.Error = fmt.Sprintf("Photon %s task exited with code %d", info.Action, *info.ExitCode)
		}
	}
	if len(instance.Errors) != 0 {
		info.Error = fmt.Sprintf("procd Photon %s task reported errors: %v", info.Action, instance.Errors)
	}
	return info, nil
}

func (h *Handler) service(ctx context.Context, action string) error {
	if !slices.Contains([]string{"start", "stop", "restart", "enable", "disable"}, action) {
		return errors.New("unsupported service action")
	}
	if err := os.MkdirAll(h.options.RuntimeDir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(h.options.RuntimeDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("Photon runtime directory is not private")
	}
	fd, err := unix.Open(filepath.Join(h.options.RuntimeDir, "service-action.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "Photon service action lock")
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("Photon service action lock is not a regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another Photon service action is being submitted; refresh and retry")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	state, err := h.readServiceAction(ctx)
	if err != nil {
		return err
	}
	if state.Running == nil || *state.Running {
		return errors.New("a Photon service action is still running; wait for its completion")
	}
	return h.serviceLocked(ctx, action)
}

func (h *Handler) scheduleServiceAction(ctx context.Context, action string) error {
	if action != "stop" && action != "restart" {
		return errors.New("only stop and restart may be scheduled")
	}
	// No shell, respawn, helper process or caller-selected command. PID 1 owns
	// this one-shot init invocation after the ubus request/RPC process exits.
	request := map[string]any{
		"name":      serviceActionName,
		"autostart": true,
		"data":      map[string]string{"owner": serviceActionOwner},
		"instances": map[string]any{"main": map[string]any{
			"command": []string{h.options.InitPath, action},
			"data":    map[string]string{"owner": serviceActionOwner, "action": action},
			"stdout":  true, "stderr": true,
		}},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if _, err := h.options.Run(ctx, "ubus", "call", "service", "set", string(encoded)); err != nil {
		return fmt.Errorf("submit Photon %s task to procd: %w", action, err)
	}
	return nil
}
