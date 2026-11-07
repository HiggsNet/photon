package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/HiggsNet/photon/internal/mihomoproxy"
	"github.com/HiggsNet/photon/internal/photonwindows"
)

func (b *desktopBackend) proxyDirectory(ctx context.Context) (*photonwindows.ServiceDirectory, error) {
	b.mu.Lock()
	run := b.run
	b.mu.Unlock()
	if run == nil || run.ctx.Err() != nil {
		return nil, nil
	}
	select {
	case <-run.ready:
	case <-run.done:
		return nil, nil
	default:
		return nil, nil
	}
	response, err := run.call(ctx, "status")
	if err != nil {
		return nil, err
	}
	observation, err := desktopObservation(response)
	if err != nil || !observation.TunnelReady {
		return nil, err
	}
	response, err = run.call(ctx, "services")
	if err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, response.Error
	}
	if response.Version != photonwindows.ControlVersion || response.Method != "services" {
		return nil, errors.New("invalid Photon service directory response")
	}
	var directory photonwindows.ServiceDirectory
	if err := json.Unmarshal(response.Result, &directory); err != nil {
		return nil, err
	}
	b.mu.Lock()
	sameRun := b.run == run
	b.mu.Unlock()
	select {
	case <-run.done:
		return nil, nil
	default:
	}
	if !sameRun || run.ctx.Err() != nil {
		return nil, nil
	}
	return &directory, nil
}

func readProxyTemplate(path string, optional bool) (mihomoproxy.Template, error) {
	if path == "" {
		return mihomoproxy.Template{}, nil
	}
	file, err := os.Open(path)
	if optional && errors.Is(err, os.ErrNotExist) {
		return mihomoproxy.Template{}, nil
	}
	if err != nil {
		return mihomoproxy.Template{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return mihomoproxy.Template{}, err
	}
	if !info.Mode().IsRegular() {
		return mihomoproxy.Template{}, errors.New("代理模板必须是普通文件")
	}
	content, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil {
		return mihomoproxy.Template{}, err
	}
	return mihomoproxy.ParseTemplate(content)
}
