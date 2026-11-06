package configedit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

// Editor retains the file identity and bytes observed by one editing session.
// Callers serialize its operations.
type Editor struct {
	path          string
	loaded        os.FileInfo
	loadAttempted bool
	formLoaded    bool
	formMOBIKE    bool
	digest        [32]byte
}

func New(path string) *Editor { return &Editor{path: path} }

func Read(path string) ([]byte, os.FileInfo, error) {
	f, err := Open(path)
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

func (b *Editor) LoadText() (string, error) {
	b.formLoaded = false
	data, info, err := Read(b.path)
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

func Parse(text string) (*photonwindows.Config, error) {
	config, err := photonwindows.ParseConfig(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config.State.Path) {
		return nil, errors.New("desktop configuration requires an absolute state.path")
	}
	return config, nil
}

func (b *Editor) SaveText(text string) error {
	if len(text) > 1<<20 {
		return errors.New("config exceeds 1 MiB")
	}
	if _, err := Parse(text); err != nil {
		return err
	}
	if !b.loadAttempted {
		return errors.New("load the configuration before saving")
	}
	check := func() error {
		current, info, err := Read(b.path)
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
	temp, err := os.CreateTemp(filepath.Dir(b.path), ".photon-config-*")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("configuration directory %q does not exist; create it before saving: %w", filepath.Dir(b.path), err)
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
	if err := prepareReplacement(b.path, temp, mode); err != nil {
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
	if err := Replace(temp.Name(), b.path, b.loaded != nil); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	data, info, err := Read(b.path)
	if err != nil {
		return fmt.Errorf("configuration saved but verification failed: %w", err)
	}
	if string(data) != text {
		return errors.New("configuration changed immediately after saving; reload")
	}
	b.loaded, b.digest = info, sha256.Sum256(data)
	return nil
}
