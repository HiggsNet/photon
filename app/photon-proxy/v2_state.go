package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
	bolt "go.etcd.io/bbolt"
)

var v2StateKey = []byte("node-v2")

type v2DiskState struct {
	SigningKey   []byte                          `json:"signing_key,omitempty"`
	TLS          v2TLSState                      `json:"tls"`
	Ports        map[string]service.ProxyV2Ports `json:"ports"`
	Activated    map[string]time.Time            `json:"activated"`
	Pending      map[string]service.ProxyV2Ports `json:"pending,omitempty"`
	LastRotation string                          `json:"last_rotation,omitempty"`
}

func (s *routeState) loadV2() (v2DiskState, error) {
	var local v2DiskState
	err := s.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(routeBucket)
		if bucket == nil || bucket.Get(v2StateKey) == nil {
			return nil
		}
		return json.Unmarshal(bucket.Get(v2StateKey), &local)
	})
	if local.Ports == nil {
		local.Ports = make(map[string]service.ProxyV2Ports)
	}
	if local.Activated == nil {
		local.Activated = make(map[string]time.Time)
	}
	return local, err
}

func (s *routeState) saveV2(local v2DiskState) error {
	raw, err := json.Marshal(local)
	if err != nil {
		return err
	}
	return s.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(routeBucket)
		if err != nil {
			return err
		}
		return bucket.Put(v2StateKey, raw)
	})
}

func prepareV2StateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state_dir must be private, for example mode 0700")
	}
	stateFile := filepath.Join(path, "state.db")
	info, err = os.Lstat(stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("proxy state.db must be a private regular file")
	}
	return nil
}

type v2RotationRequest struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	TLS   bool   `json:"tls"`
}

const v2RotationFile = "rotate.json"

func requestV2Rotation(dir string, request v2RotationRequest) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "rotate-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Link(file.Name(), filepath.Join(dir, v2RotationFile))
}
