//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/internal/photonwindows/configedit"
	"golang.org/x/sys/windows"
)

func elevatedConfigCopy(source, destination string) error {
	if !photonwindows.FrontendNeedsElevation() {
		return configedit.Copy(source, destination)
	}
	config, err := photonwindows.LoadConfig(source)
	if err != nil {
		return err
	}
	if _, err := os.Stat(config.State.Path); errors.Is(err, os.ErrNotExist) {
		return configedit.Copy(source, destination)
	}
	data, err := readFrontendConfig(source)
	if err != nil {
		return err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	handle, name, err := photonwindows.ListenFrontendPipe()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	worker, err := launchFrontendWorker(executable, []string{"config-copy-worker", strconv.Itoa(os.Getpid()), name, digest, source, destination})
	if err != nil {
		return err
	}
	defer windows.CloseHandle(worker)
	defer func() {
		_ = windows.DisconnectNamedPipe(handle)
		_, _ = windows.WaitForSingleObject(worker, windows.INFINITE)
	}()
	pid, err := windows.GetProcessId(worker)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := photonwindows.AcceptFrontendWorker(ctx, handle, pid); err != nil {
		return err
	}
	stream := photonwindows.FrontendPipeStream(ctx, handle)
	defer stream.Close()
	var reply struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(stream).Decode(&reply); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	return nil
}

func runConfigCopyWorker(args []string, stderr io.Writer) int {
	if len(args) != 5 || photonwindows.FrontendNeedsElevation() {
		return 2
	}
	pid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil || pid == 0 || !filepath.IsAbs(args[3]) || !filepath.IsAbs(args[4]) {
		return 2
	}
	executable, err := os.Executable()
	if err != nil {
		return 1
	}
	parent, err := photonwindows.VerifyFrontendProcess(uint32(pid), executable)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer windows.CloseHandle(parent)
	handle, err := photonwindows.OpenFrontendPipe(args[1], uint32(pid))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer windows.CloseHandle(handle)
	data, err := readFrontendConfig(args[3])
	if err == nil && fmt.Sprintf("%x", sha256.Sum256(data)) != args[2] {
		err = errors.New("configuration changed during elevation")
	}
	if err == nil {
		err = configedit.Copy(args[3], args[4])
	}
	reply := struct {
		Error string `json:"error"`
	}{}
	if err != nil {
		reply.Error = err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := photonwindows.FrontendPipeStream(ctx, handle)
	defer stream.Close()
	if json.NewEncoder(stream).Encode(reply) != nil {
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}
