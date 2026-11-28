package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"gopkg.in/yaml.v3"
)

// Copy copies the Photon identity and rule template, preserving references to
// separately managed proxy configurations.
func Copy(source, destination string) (err error) {
	if !filepath.IsAbs(source) || !filepath.IsAbs(destination) {
		return errors.New("configuration paths must be absolute")
	}
	original, _, err := Read(source)
	if err != nil {
		return err
	}
	config, err := Parse(string(original))
	if err != nil {
		return err
	}
	if err := config.ResolvePaths(source); err != nil {
		return err
	}
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("choose an empty destination directory; existing files are never overwritten")
	}
	var created []string
	defer func() {
		if err != nil {
			if _, statErr := os.Lstat(destination); statErr == nil {
				return
			}
			for _, path := range created {
				_ = os.Remove(path)
			}
		}
	}()
	base := strings.TrimSuffix(filepath.Base(destination), filepath.Ext(destination))
	stateName := base + ".db"
	if strings.EqualFold(stateName, filepath.Base(destination)) {
		stateName = base + ".state.db"
	}
	statePath := filepath.Join(dir, stateName)
	if _, statErr := os.Stat(config.State.Path); statErr == nil {
		if err := photonwindows.CopyState(config, statePath); err != nil {
			return fmt.Errorf("copy identity (stop Photon and allow administrator access): %w", err)
		}
		created = append(created, statePath)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	sourceTemplate := strings.TrimSuffix(source, filepath.Ext(source)) + ".proxy.yaml"
	targetTemplate := filepath.Join(dir, base+".proxy.yaml")
	if info, statErr := os.Lstat(sourceTemplate); statErr == nil {
		if !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return errors.New("proxy template must be a regular file of at most 4 MiB")
		}
		file, err := Open(sourceTemplate)
		if err != nil {
			return err
		}
		content, readErr := io.ReadAll(io.LimitReader(file, (4<<20)+1))
		if err := errors.Join(readErr, file.Close()); err != nil {
			return err
		}
		if len(content) > 4<<20 {
			return errors.New("proxy template exceeds 4 MiB")
		}
		if err := writeNewFile(targetTemplate, content); err != nil {
			return err
		}
		created = append(created, targetTemplate)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	var document yaml.Node
	if err := yaml.Unmarshal(original, &document); err != nil {
		return err
	}
	mapping := document.Content[0]
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "proxy_v2_config" && config.ProxyV2ConfigPath != "" {
			mapping.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: config.ProxyV2ConfigPath}
			continue
		}
		if mapping.Content[i].Value != "state" {
			continue
		}
		state := mapping.Content[i+1]
		if state.Kind == yaml.AliasNode {
			state = state.Alias
		}
		for j := 0; j < len(state.Content); j += 2 {
			if state.Content[j].Value == "path" {
				state.Content[j+1].SetString(stateName)
			}
		}
	}
	content, err := yaml.Marshal(&document)
	if err != nil {
		return err
	}
	relocated, err := Parse(string(content))
	if err != nil {
		return err
	}
	if relocated.State.Path != stateName {
		return errors.New("cannot relocate state.path in this YAML; use a direct state mapping")
	}
	if relocated.ProxyV2ConfigPath != config.ProxyV2ConfigPath {
		return errors.New("cannot preserve proxy_v2_config in this YAML; use a direct path")
	}
	current, _, err := Read(source)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, original) {
		return errors.New("source configuration changed during copy; try again")
	}
	editor := New(destination)
	if _, err := editor.LoadText(); !errors.Is(err, os.ErrNotExist) {
		return errors.New("destination configuration already exists")
	}
	if err := editor.SaveText(string(content)); err != nil {
		return err
	}
	return nil
}

func writeNewFile(path string, content []byte) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	return file.Sync()
}
