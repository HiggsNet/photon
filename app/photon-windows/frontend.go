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

func runFrontendBackend(ctx context.Context, path string, stdout, stderr io.Writer) int {
	stream := frontendStream{Reader: os.Stdin, Writer: stdout}
	fail := func(err error) int {
		_ = photonwindows.WriteControlReady(stdout, photonwindows.ControlReady{}, err)
		fmt.Fprintln(stderr, err)
		return 1
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fail(err)
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
	runErr := photonwindows.RunControlStream(ctx, photonwindows.NewDaemon(config, logger), fmt.Sprintf("%x", sha256.Sum256(data)), stream)
	if err := errors.Join(runErr, closer.Close()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
