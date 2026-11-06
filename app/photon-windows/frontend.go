package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

type frontendStream struct {
	io.Reader
	io.Writer
}

func (s frontendStream) Close() error {
	var err error
	if closer, ok := s.Reader.(io.Closer); ok {
		err = closer.Close()
	}
	if closer, ok := s.Writer.(io.Closer); ok {
		err = errors.Join(err, closer.Close())
	}
	return err
}

func readFrontendConfig(path string) ([]byte, error) {
	const limit = 1 << 20
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if len(data) > limit {
		return nil, errors.New("Photon configuration is too large")
	}
	return data, err
}

func runFrontendBackend(ctx context.Context, path string, stream io.ReadWriteCloser, expectedDigest string, stderr io.Writer) int {
	fail := func(err error) int {
		_ = photonwindows.WriteControlReady(stream, photonwindows.ControlReady{}, err)
		fmt.Fprintln(stderr, err)
		return 1
	}
	data, err := readFrontendConfig(path)
	if err != nil {
		return fail(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if expectedDigest != "" && digest != expectedDigest {
		return fail(errors.New("Photon configuration changed during elevation"))
	}
	config, err := photonwindows.ParseConfig(strings.NewReader(string(data)))
	if err != nil {
		return fail(err)
	}
	if !filepath.IsAbs(path) || !filepath.IsAbs(config.State.Path) {
		return fail(errors.New("frontend backend requires absolute config and state paths"))
	}
	logger, closer, err := photonwindows.NewRuntimeLogger(config, nil, "")
	if err != nil {
		return fail(err)
	}
	runErr := photonwindows.RunControlStream(ctx, photonwindows.NewDaemon(config, logger), digest, stream)
	if err := errors.Join(runErr, closer.Close()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
