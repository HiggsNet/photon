package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

// Text fields retain incomplete edits until Save; the persisted YAML schema
// and its semantic validation belong exclusively to photonwindows.ConfigOptions.
type desktopConfigForm struct {
	// NewConfig describes a successful load of a missing file; it is not persisted.
	NewConfig                                                bool
	RootPublicKey, ManagedZone, AllowedGateways, SplitRoutes string
	StatePath, OverlayID, GossipListen, AdapterName, MTU     string
	LogLevel, InitialBackoff, MaxBackoff                     string
	BootstrapHints                                           []desktopBootstrapRow
}

type desktopBootstrapRow struct{ Peer, Address string }

func defaultDesktopConfigForm(configPath string) desktopConfigForm {
	base := filepath.Base(configPath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" {
		base = "photon"
	}
	statePath := filepath.Join(filepath.Dir(configPath), base+".db")
	if strings.EqualFold(statePath, configPath) {
		statePath = filepath.Join(filepath.Dir(configPath), base+".state.db")
	}
	return desktopConfigForm{
		StatePath: statePath, OverlayID: "ipsec-main", GossipListen: "0.0.0.0:33434",
		AdapterName: "Photon Windows", MTU: "1400", LogLevel: "info", InitialBackoff: "1s", MaxBackoff: "1m",
	}
}

func desktopFormFromConfig(config *photonwindows.Config) desktopConfigForm {
	form := desktopConfigForm{
		RootPublicKey: base64.StdEncoding.EncodeToString(config.TrustedRootPublicKey), ManagedZone: string(config.ManagedZone),
		StatePath: config.State.Path, OverlayID: config.Overlay.ID, GossipListen: config.GossipListen,
		AdapterName: config.Wintun.AdapterName, MTU: strconv.Itoa(config.Wintun.MTU), LogLevel: config.Log.Level,
		InitialBackoff: config.Reconnect.InitialBackoff.String(), MaxBackoff: config.Reconnect.MaxBackoff.String(),
	}
	var routes, gateways []string
	for _, route := range config.Overlay.SplitRoutes {
		routes = append(routes, route.String())
	}
	for _, gateway := range config.Gateway.AllowedZones {
		gateways = append(gateways, string(gateway))
	}
	form.SplitRoutes, form.AllowedGateways = strings.Join(routes, "\r\n"), strings.Join(gateways, "\r\n")
	for _, hint := range config.Gateway.BootstrapHints {
		form.BootstrapHints = append(form.BootstrapHints, desktopBootstrapRow{Peer: string(hint.Peer), Address: hint.Address})
	}
	return form
}

func desktopFormLines(text string) []string {
	var values []string
	for _, line := range strings.Split(text, "\n") {
		if value := strings.TrimSpace(line); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func desktopFormText(form desktopConfigForm) (string, error) {
	var options photonwindows.ConfigOptions
	options.SchemaVersion = photonwindows.ConfigSchemaVersion
	options.TrustedRootPublicKey, options.ManagedZone = form.RootPublicKey, form.ManagedZone
	options.State.Path, options.GossipListen = form.StatePath, form.GossipListen
	options.Overlay.ID, options.Overlay.SplitRoutes = form.OverlayID, desktopFormLines(form.SplitRoutes)
	options.Gateway.AllowedZones = desktopFormLines(form.AllowedGateways)
	for _, row := range form.BootstrapHints {
		if strings.TrimSpace(row.Peer) == "" && strings.TrimSpace(row.Address) == "" {
			continue
		}
		options.Gateway.BootstrapHints = append(options.Gateway.BootstrapHints, photonwindows.BootstrapHintOptions{Peer: row.Peer, Address: row.Address})
	}
	options.Wintun.AdapterName = form.AdapterName
	if value := strings.TrimSpace(form.MTU); value != "" {
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("MTU must be an integer: %w", err)
		}
		options.Wintun.MTU = mtu
	}
	options.Log.Level = form.LogLevel
	options.Reconnect.InitialBackoff, options.Reconnect.MaxBackoff = form.InitialBackoff, form.MaxBackoff
	data, err := photonwindows.MarshalConfig(options)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (b *desktopBackend) LoadForm() (desktopConfigForm, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	text, err := b.loadConfigText()
	if errors.Is(err, os.ErrNotExist) {
		b.formLoaded = true
		form := defaultDesktopConfigForm(b.options.ConfigPath)
		form.NewConfig = true
		return form, nil
	}
	if err != nil {
		return desktopConfigForm{}, err
	}
	config, err := desktopParseConfig(text)
	if err != nil {
		return desktopConfigForm{}, err
	}
	b.formLoaded = true
	return desktopFormFromConfig(config), nil
}

func (b *desktopBackend) SaveForm(form desktopConfigForm) error {
	text, err := desktopFormText(form)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.formLoaded {
		return errors.New("configuration form did not load successfully; correct the existing file and reload before saving")
	}
	return b.saveConfigText(text)
}
