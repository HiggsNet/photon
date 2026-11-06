package configedit

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
type Form struct {
	NewConfig       bool           `json:"new_config"`
	RootPublicKey   string         `json:"root_public_key"`
	ManagedZone     string         `json:"managed_zone"`
	AllowedGateways string         `json:"allowed_gateways"`
	MOBIKE          *bool          `json:"mobike,omitempty"`
	SplitRoutes     string         `json:"split_routes"`
	StatePath       string         `json:"state_path"`
	OverlayID       string         `json:"overlay_id"`
	GossipListen    string         `json:"gossip_listen"`
	AdapterName     string         `json:"adapter_name"`
	MTU             string         `json:"mtu"`
	LogLevel        string         `json:"log_level"`
	InitialBackoff  string         `json:"initial_backoff"`
	MaxBackoff      string         `json:"max_backoff"`
	BootstrapHints  []BootstrapRow `json:"bootstrap_hints"`
}

type BootstrapRow struct {
	Peer    string `json:"peer"`
	Address string `json:"address"`
}

func DefaultForm(configPath string) Form {
	base := filepath.Base(configPath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" {
		base = "photon"
	}
	statePath := filepath.Join(filepath.Dir(configPath), base+".db")
	if strings.EqualFold(statePath, configPath) {
		statePath = filepath.Join(filepath.Dir(configPath), base+".state.db")
	}
	return Form{
		AllowedGateways: "*",
		StatePath:       statePath, OverlayID: "ipsec-main", GossipListen: "0.0.0.0:33434",
		AdapterName: "Photon Windows", MTU: "1400", LogLevel: "info", InitialBackoff: "1s", MaxBackoff: "1m",
	}
}

func FromConfig(config *photonwindows.Config) Form {
	form := Form{
		RootPublicKey: base64.StdEncoding.EncodeToString(config.TrustedRootPublicKey), ManagedZone: string(config.ManagedZone),
		StatePath: config.State.Path, OverlayID: config.Overlay.ID, GossipListen: config.GossipListen,
		AdapterName: config.Wintun.AdapterName, MTU: strconv.Itoa(config.Wintun.MTU), LogLevel: config.Log.Level,
		InitialBackoff: config.Reconnect.InitialBackoff.String(), MaxBackoff: config.Reconnect.MaxBackoff.String(),
	}
	if config.Gateway.MOBIKE {
		mobike := true
		form.MOBIKE = &mobike
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
		form.BootstrapHints = append(form.BootstrapHints, BootstrapRow{Peer: string(hint.Peer), Address: hint.Address})
	}
	return form
}

func Lines(text string) []string {
	var values []string
	for _, line := range strings.Split(text, "\n") {
		if value := strings.TrimSpace(line); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func FormText(form Form) (string, error) {
	var options photonwindows.ConfigOptions
	options.SchemaVersion = photonwindows.ConfigSchemaVersion
	options.TrustedRootPublicKey, options.ManagedZone = form.RootPublicKey, form.ManagedZone
	options.State.Path, options.GossipListen = form.StatePath, form.GossipListen
	options.Overlay.ID, options.Overlay.SplitRoutes = form.OverlayID, Lines(form.SplitRoutes)
	options.Gateway.AllowedZones = Lines(form.AllowedGateways)
	if form.MOBIKE != nil {
		options.Gateway.MOBIKE = *form.MOBIKE
	}
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

func (b *Editor) LoadForm() (Form, error) {
	text, err := b.LoadText()
	if errors.Is(err, os.ErrNotExist) {
		b.formLoaded = true
		b.formMOBIKE = false
		form := DefaultForm(b.path)
		form.NewConfig = true
		return form, nil
	}
	if err != nil {
		return Form{}, err
	}
	config, err := Parse(text)
	if err != nil {
		return Form{}, err
	}
	b.formLoaded = true
	b.formMOBIKE = config.Gateway.MOBIKE
	return FromConfig(config), nil
}

func (b *Editor) SaveForm(form Form) error {
	if !b.formLoaded {
		return errors.New("configuration form did not load successfully; correct the existing file and reload before saving")
	}
	mobike := b.formMOBIKE
	if form.MOBIKE != nil {
		mobike = *form.MOBIKE
	}
	form.MOBIKE = &mobike
	text, err := FormText(form)
	if err != nil {
		return err
	}
	if err := b.SaveText(text); err != nil {
		return err
	}
	b.formMOBIKE = mobike
	return nil
}
