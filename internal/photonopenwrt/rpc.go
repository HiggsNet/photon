//go:build linux

// Package photonopenwrt adapts local Photon management to rpcd. It owns no
// protocol state and never starts a daemon outside the system init service.
package photonopenwrt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const MaxConfigBytes = 128 << 10

type Runner func(context.Context, string, ...string) ([]byte, error)
type Views struct {
	Daemon  json.RawMessage
	Summary json.RawMessage
	Peers   json.RawMessage
	Links   json.RawMessage
}

type ViewsReader func(context.Context, string) (Views, error)

type Options struct {
	Run               Runner
	Validate          func(string) error
	Views             ViewsReader
	IntegrationStatus func(context.Context, string) (json.RawMessage, error)
	LookPath          func(string) (string, error)
	RuntimeDir        string
	DefaultConfigPath string
	ExamplePath       string
	InitPath          string
	PreflightPath     string
}

type Handler struct{ options Options }

func New(options Options) *Handler {
	if options.Run == nil {
		options.Run = runCommand
	}
	if options.LookPath == nil {
		options.LookPath = exec.LookPath
	}
	if options.RuntimeDir == "" {
		options.RuntimeDir = "/run/photon"
	}
	if options.DefaultConfigPath == "" {
		options.DefaultConfigPath = "/etc/photon/config.yaml"
	}
	if options.ExamplePath == "" {
		options.ExamplePath = "/etc/photon/config.yaml.example"
	}
	if options.InitPath == "" {
		options.InitPath = "/etc/init.d/photon"
	}
	if options.PreflightPath == "" {
		options.PreflightPath = "/usr/libexec/photon-preflight"
	}
	return &Handler{options: options}
}

// Serve implements rpcd's executable plugin protocol. Errors are returned in a
// JSON envelope so the panel can keep the user's unsaved configuration intact.
func (h *Handler) Serve(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 1 && args[0] == "list" {
		return json.NewEncoder(output).Encode(map[string]any{
			"snapshot": map[string]any{}, "get_config": map[string]any{},
			"validate_config": map[string]any{"content": ""},
			"save_config":     map[string]any{"content": "", "sha256": ""},
			"service":         map[string]any{"action": ""}, "diagnostics": map[string]any{},
			"network_settings":      map[string]any{},
			"save_network_settings": map[string]any{"settings": "", "sha256": ""},
		})
	}
	response := map[string]any{"ok": false}
	if len(args) != 2 || args[0] != "call" {
		response["error"] = "invalid rpcd invocation"
	} else {
		var err error
		response, err = h.call(ctx, args[1], input)
		if err != nil {
			response = map[string]any{"ok": false, "error": err.Error()}
		}
	}
	return json.NewEncoder(output).Encode(response)
}

func (h *Handler) call(ctx context.Context, method string, input io.Reader) (map[string]any, error) {
	request, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if err != nil || len(request) > 1<<20 {
		return nil, errors.New("request exceeds 1 MiB or could not be read")
	}
	var arguments map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(request))
	if err := decoder.Decode(&arguments); err != nil || arguments == nil {
		return nil, errors.New("request must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("request must contain one JSON object")
	}
	allowed := map[string][]string{
		"snapshot": {}, "get_config": {}, "diagnostics": {}, "network_settings": {},
		"validate_config": {"content"}, "save_config": {"content", "sha256"}, "service": {"action"},
		"save_network_settings": {"settings", "sha256"},
	}
	fields, exists := allowed[method]
	if !exists {
		return nil, errors.New("unknown Photon management method")
	}
	delete(arguments, "ubus_rpc_session") // rpcd supplies the authenticated session.
	for name := range arguments {
		found := false
		for _, field := range fields {
			found = found || name == field
		}
		if !found {
			return nil, fmt.Errorf("unexpected argument %q", name)
		}
	}
	values := make(map[string]string)
	for _, name := range fields {
		raw, found := arguments[name]
		var value string
		if !found || string(raw) == "null" || json.Unmarshal(raw, &value) != nil {
			return nil, fmt.Errorf("argument %q must be a string", name)
		}
		values[name] = value
	}
	switch method {
	case "snapshot":
		return h.snapshot(ctx), nil
	case "get_config":
		return h.getConfig(ctx)
	case "validate_config":
		return map[string]any{"ok": true}, h.validate(values["content"])
	case "save_config":
		return h.saveConfig(ctx, values["content"], values["sha256"])
	case "service":
		err := h.service(ctx, values["action"])
		response := map[string]any{"ok": true}
		if values["action"] == "stop" || values["action"] == "restart" {
			response["scheduled"], response["action"] = true, values["action"]
		}
		return response, err
	case "diagnostics":
		return h.diagnostics(ctx), nil
	case "network_settings":
		return h.networkSettings(ctx)
	case "save_network_settings":
		return h.saveNetworkSettings(ctx, values["settings"], values["sha256"])
	}
	return nil, errors.New("unknown method")
}

func (h *Handler) validate(content string) error {
	if strings.TrimSpace(content) == "" || len(content) > MaxConfigBytes {
		return errors.New("configuration must contain 1 to 131072 bytes")
	}
	if h.options.Validate == nil {
		return errors.New("configuration validator unavailable")
	}
	return h.options.Validate(content)
}

func (h *Handler) configPath(ctx context.Context) (string, error) {
	path := h.options.DefaultConfigPath
	if value, err := h.options.Run(ctx, "uci", "-q", "get", "photon.main.config_file"); err == nil {
		path = strings.TrimSpace(string(value))
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || (filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml") {
		return "", errors.New("configured file must be an absolute .yaml or .yml path")
	}
	return path, nil
}

func readConfig(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("configuration must be a regular file, not a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if len(data) > MaxConfigBytes {
		return nil, false, errors.New("configuration exceeds 128 KiB")
	}
	return data, true, err
}

func configHash(data []byte, exists bool) string {
	if !exists {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (h *Handler) getConfig(ctx context.Context) (map[string]any, error) {
	path, err := h.configPath(ctx)
	if err != nil {
		return nil, err
	}
	data, exists, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	hash := configHash(data, exists)
	if !exists {
		data, _, err = readConfig(h.options.ExamplePath)
		if err != nil {
			return nil, err
		}
	}
	return map[string]any{"ok": true, "path": path, "exists": exists, "content": string(data), "sha256": hash}, nil
}

func (h *Handler) saveConfig(ctx context.Context, content, expectedHash string) (map[string]any, error) {
	if err := h.validate(content); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(h.options.RuntimeDir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(h.options.RuntimeDir, "config.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("configuration is being updated; retry after refreshing")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	path, err := h.configPath(ctx)
	if err != nil {
		return nil, err
	}
	previous, exists, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	if configHash(previous, exists) != expectedHash {
		return nil, errors.New("configuration changed since it was loaded; refresh before saving")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(directory, ".photon-config-*.yaml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := io.WriteString(file, content); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return nil, err
	}
	// The rename is the commit point. A directory-sync issue cannot turn a
	// committed update into an error claiming the previous file was retained.
	if dir, err := os.Open(directory); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return map[string]any{"ok": true, "sha256": configHash([]byte(content), true)}, nil
}

type serviceInfo struct {
	Running     bool              `json:"running"`
	PID         int               `json:"pid"`
	Enabled     *bool             `json:"enabled"`
	BootEnabled *bool             `json:"boot_enabled"`
	Error       string            `json:"error,omitempty"`
	Action      serviceActionInfo `json:"action"`
}

func (h *Handler) enabled(ctx context.Context) (bool, error) {
	value, err := h.options.Run(ctx, "uci", "-q", "get", "photon.main.enabled")
	if err != nil {
		// A missing UCI option follows the init script's default-disabled rule.
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}
	switch strings.TrimSpace(string(value)) {
	case "1", "on", "true", "yes", "enabled":
		return true, nil
	case "0", "off", "false", "no", "disabled", "":
		return false, nil
	}
	return false, errors.New("invalid Photon service switch")
}

func (h *Handler) snapshot(ctx context.Context) map[string]any {
	service := serviceInfo{}
	if action, err := h.readServiceAction(ctx); err != nil {
		service.Action.Error = err.Error()
	} else {
		service.Action = action
	}
	var warnings []string
	if enabled, err := h.enabled(ctx); err == nil {
		service.Enabled = &enabled
	} else {
		warnings = append(warnings, "service enable setting unavailable")
	}
	_, err := h.options.Run(ctx, h.options.InitPath, "enabled")
	var exit *exec.ExitError
	if err == nil || (errors.As(err, &exit) && exit.ExitCode() == 1) {
		bootEnabled := err == nil
		service.BootEnabled = &bootEnabled
	} else {
		warnings = append(warnings, "boot enable setting unavailable")
	}
	data, err := h.options.Run(ctx, "ubus", "call", "service", "list", `{"name":"photon"}`)
	if err != nil {
		service.Error = "procd service state unavailable"
	} else {
		var services map[string]struct {
			Instances map[string]struct {
				Running bool `json:"running"`
				PID     int  `json:"pid"`
			} `json:"instances"`
		}
		if err := json.Unmarshal(data, &services); err != nil || services == nil {
			service.Error = "invalid procd service response"
		} else {
			instance := services["photon"].Instances["main"]
			service.Running, service.PID = instance.Running, instance.PID
		}
	}
	response := map[string]any{"ok": true, "service": service, "daemon": nil, "summary": nil, "peers": nil, "links": nil}
	path, err := h.configPath(ctx)
	if err == nil && h.options.Views != nil {
		var views Views
		views, err = h.options.Views(ctx, path)
		if err == nil {
			response["daemon"], response["summary"] = views.Daemon, views.Summary
			response["peers"], response["links"] = views.Peers, views.Links
		}
	}
	if err != nil {
		warnings = append(warnings, err.Error())
	}
	if len(warnings) != 0 {
		response["error"] = strings.Join(warnings, "; ")
	}
	return response
}

func (h *Handler) serviceLocked(ctx context.Context, action string) error {
	switch action {
	case "start", "restart":
		enabled, err := h.enabled(ctx)
		if err != nil {
			return fmt.Errorf("read Photon service switch: %w", err)
		}
		if !enabled {
			return errors.New("enable Photon before starting it")
		}
		path, err := h.configPath(ctx)
		if err != nil {
			return err
		}
		data, exists, err := readConfig(path)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("save a configuration before starting Photon")
		}
		if err := h.validate(string(data)); err != nil {
			return err
		}
	case "stop":
	case "enable", "disable":
		value := "0"
		if action == "enable" {
			value = "1"
		}
		if _, err := h.options.Run(ctx, "uci", "set", "photon.main.enabled="+value); err != nil {
			return fmt.Errorf("update service setting: %w", err)
		}
		if _, err := h.options.Run(ctx, "uci", "commit", "photon"); err != nil {
			return fmt.Errorf("commit service setting: %w", err)
		}
	default:
		return errors.New("unsupported service action")
	}
	if action == "stop" || action == "restart" {
		return h.scheduleServiceAction(ctx, action)
	}
	if _, err := h.options.Run(ctx, h.options.InitPath, action); err != nil {
		return fmt.Errorf("Photon service %s failed: %w", action, err)
	}
	return nil
}

func (h *Handler) diagnostics(ctx context.Context) map[string]any {
	type check struct {
		Name      string `json:"name"`
		Available bool   `json:"available"`
		Detail    string `json:"detail,omitempty"`
	}
	checks := make([]check, 0, 8)
	for _, name := range []string{"ip", "bird", "birdc", "nft", "swanctl", "ping", "sysctl"} {
		path, err := h.options.LookPath(name)
		checks = append(checks, check{Name: name, Available: err == nil, Detail: path})
	}
	for _, path := range []string{"/proc/self/ns/net", "/sys/module/xfrm_interface", "/sys/module/veth"} {
		_, err := os.Stat(path)
		checks = append(checks, check{Name: path, Available: err == nil})
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	preflight, err := h.options.Run(probeCtx, h.options.PreflightPath)
	log, logErr := h.options.Run(ctx, "logread", "-l", "80", "-e", "photon")
	response := map[string]any{"ok": true, "checks": checks, "log": string(log), "preflight": string(preflight)}
	if err != nil {
		response["error"] = "some preflight checks failed or timed out; see diagnostics"
	}
	if logErr != nil {
		response["log"] = "service log unavailable"
	}
	return response
}

// Limit command output as well as execution time. No client-controlled command
// or shell text is accepted; all callers above supply fixed executable names.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	// A preflight shell may itself be blocked in swanctl. Cancel the entire
	// command group so a timeout cannot leave diagnostic children behind.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	limit := commandOutputLimit(name, args)
	output := &limitedBuffer{limit: limit}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	if output.truncated && limit == structuredCommandOutputLimit {
		// The partial document is unusable JSON. Do not copy megabytes into a
		// caller's diagnostic error when reporting this explicit failure.
		return nil, errors.Join(err, fmt.Errorf("%w: %d bytes", errStructuredOutputTruncated, limit))
	}
	return output.Bytes(), err
}

const diagnosticCommandOutputLimit = 32 << 10
const structuredCommandOutputLimit = 8 << 20

var errStructuredOutputTruncated = errors.New("structured command output exceeded limit")

func commandOutputLimit(name string, args []string) int {
	if name == "nft" && slices.Equal(args, []string{"-j", "list", "ruleset"}) ||
		name == "ubus" && slices.Equal(args, []string{"call", "network.interface", "dump"}) {
		return structuredCommandOutputLimit
	}
	return diagnosticCommandOutputLimit
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *limitedBuffer) Write(data []byte) (int, error) {
	count := len(data)
	limit := b.limit
	if limit == 0 {
		limit = diagnosticCommandOutputLimit
	}
	remaining := limit - b.buffer.Len()
	if count > remaining {
		b.truncated = true
	}
	if remaining > 0 {
		_, _ = b.buffer.Write(data[:min(remaining, count)])
	}
	return count, nil
}
