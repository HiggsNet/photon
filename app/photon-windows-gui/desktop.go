package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/internal/photonwindows/configedit"
)

type desktopOptions struct{ ConfigPath, BackendPath string }
type desktopSnapshot struct {
	RuntimeState string
	Observation  *photonwindows.Observation
	Error        string
}

type desktopBackend struct {
	options    desktopOptions
	mu         sync.Mutex
	editor     *configedit.Editor
	runtimeMu  sync.Mutex // Serializes start, stop, restart and final cleanup.
	run        *desktopRun
	runtimeErr error
	closed     bool
}

func newDesktopBackend(options desktopOptions) (*desktopBackend, error) {
	if !filepath.IsAbs(options.ConfigPath) {
		return nil, errors.New("desktop requires an absolute config path")
	}
	options.ConfigPath = filepath.Clean(options.ConfigPath)
	return &desktopBackend{options: options, editor: configedit.New(options.ConfigPath)}, nil
}

var (
	desktopReadConfig    = configedit.Read
	desktopOpenConfig    = configedit.Open
	desktopParseConfig   = configedit.Parse
	desktopReplaceConfig = configedit.Replace
)

func (b *desktopBackend) LoadConfigText() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.editor.LoadText()
}

func (b *desktopBackend) SaveConfigText(text string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.editor.SaveText(text)
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
