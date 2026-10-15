package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

type desktopOptions struct{ ConfigPath string }
type desktopSnapshot struct {
	RuntimeState string
	Observation  *photonwindows.Observation
	Error        string
}

type desktopBackend struct {
	options       desktopOptions
	mu            sync.Mutex
	loaded        os.FileInfo
	loadAttempted bool
	formLoaded    bool
	digest        [32]byte
	runtimeMu     sync.Mutex // Serializes start, stop, restart and final cleanup.
	run           *desktopRun
	runtimeErr    error
	closed        bool
}

func newDesktopBackend(options desktopOptions) (*desktopBackend, error) {
	if !filepath.IsAbs(options.ConfigPath) {
		return nil, errors.New("desktop requires an absolute config path")
	}
	options.ConfigPath = filepath.Clean(options.ConfigPath)
	return &desktopBackend{options: options}, nil
}

func desktopReadConfig(path string) ([]byte, os.FileInfo, error) {
	f, err := desktopOpenConfig(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, nil, errors.New("config must be a regular file, not a link")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > 1<<20 {
		return nil, nil, errors.New("config exceeds 1 MiB")
	}
	return data, opened, nil
}

func (b *desktopBackend) LoadConfigText() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loadConfigText()
}

func (b *desktopBackend) loadConfigText() (string, error) {
	b.formLoaded = false
	data, info, err := desktopReadConfig(b.options.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		b.loaded = nil
		b.loadAttempted = true
		return "", err
	}
	if err != nil {
		return "", err
	}
	b.loadAttempted = true
	b.loaded, b.digest = info, sha256.Sum256(data)
	return string(data), nil
}

func desktopParseConfig(text string) (*photonwindows.Config, error) {
	config, err := photonwindows.ParseConfig(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config.State.Path) {
		return nil, errors.New("desktop configuration requires an absolute state.path")
	}
	return config, nil
}

func (b *desktopBackend) SaveConfigText(text string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.saveConfigText(text)
}

func (b *desktopBackend) saveConfigText(text string) error {
	if len(text) > 1<<20 {
		return errors.New("config exceeds 1 MiB")
	}
	if _, err := desktopParseConfig(text); err != nil {
		return err
	}
	if !b.loadAttempted {
		return errors.New("load the configuration before saving")
	}
	check := func() error {
		current, info, err := desktopReadConfig(b.options.ConfigPath)
		if b.loaded == nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			return errors.New("configuration was created outside this window; reload before saving")
		}
		if err != nil {
			return err
		}
		if !os.SameFile(b.loaded, info) || b.digest != sha256.Sum256(current) || info.Mode() != b.loaded.Mode() {
			return errors.New("configuration changed outside this window; reload before saving")
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(b.options.ConfigPath), ".photon-config-*")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("configuration directory %q does not exist; create it before saving: %w", filepath.Dir(b.options.ConfigPath), err)
		}
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	// Apply the original permissions before any configuration bytes are written.
	mode := os.FileMode(0600)
	if b.loaded != nil {
		mode = b.loaded.Mode()
	}
	if err := desktopPrepareReplacement(b.options.ConfigPath, temp, mode); err != nil {
		return err
	}
	if _, err := io.Copy(temp, bytes.NewBufferString(text)); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if err := desktopReplaceConfig(temp.Name(), b.options.ConfigPath, b.loaded != nil); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	data, info, err := desktopReadConfig(b.options.ConfigPath)
	if err != nil {
		return fmt.Errorf("configuration saved but verification failed: %w", err)
	}
	if string(data) != text {
		return errors.New("configuration changed immediately after saving; reload")
	}
	b.loaded, b.digest = info, sha256.Sum256(data)
	return nil
}

func desktopObservation(response photonwindows.ControlResponse) (*photonwindows.Observation, error) {
	if response.Error != nil {
		return nil, response.Error
	}
	if response.Version != photonwindows.ControlVersion || response.Method != "status" {
		return nil, errors.New("invalid live status response")
	}
	var observation *photonwindows.Observation
	if err := json.Unmarshal(response.Result, &observation); err != nil {
		return nil, err
	}
	if observation == nil || !observation.Running {
		return nil, errors.New("daemon is no longer running")
	}
	return observation, nil
}
