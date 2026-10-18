//go:build linux

package photonopenwrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func (h *Handler) networkSettings(ctx context.Context) (map[string]any, error) {
	current, err := h.getConfig(ctx)
	if err != nil {
		return nil, err
	}
	settings, err := integrationConfigFromYAML(current["content"].(string))
	if err != nil {
		return nil, err
	}
	response := map[string]any{"ok": true, "settings": settings, "path": current["path"], "exists": current["exists"], "sha256": current["sha256"]}
	response["runtime"] = nil
	if h.options.IntegrationStatus == nil {
		response["runtime_error"] = "OpenWrt integration runtime status unavailable"
	} else if runtime, runtimeErr := h.options.IntegrationStatus(ctx, current["path"].(string)); runtimeErr != nil {
		response["runtime_error"] = runtimeErr.Error()
	} else {
		response["runtime"] = runtime
	}
	inventory, inventoryErr := ReadNetworkInventory(ctx, h.options.Run)
	response["inventory"] = inventory
	status := map[string]any{"enabled": settings.Enabled(), "ready": false}
	response["status"] = status
	if inventoryErr != nil {
		response["inventory_error"], status["error"] = inventoryErr.Error(), inventoryErr.Error()
		return response, nil
	}
	selected, err := ResolveWANNetworks(settings, inventory)
	if err == nil && settings.AnnounceIPsec {
		count := 0
		for _, network := range selected {
			count += len(network.IPv4) + len(network.IPv6)
		}
		if count == 0 {
			err = errors.New("selected WAN logical networks have no eligible unicast addresses")
		}
	}
	if err != nil {
		status["error"] = err.Error()
	} else {
		status["ready"] = true
	}
	return response, nil
}

func (h *Handler) saveNetworkSettings(ctx context.Context, encoded, expectedHash string) (map[string]any, error) {
	if !strings.HasPrefix(strings.TrimSpace(encoded), "{") {
		return nil, errors.New("network settings must be a JSON object")
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var settings Config
	if err := decoder.Decode(&settings); err != nil {
		return nil, fmt.Errorf("invalid network settings: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("network settings must contain one JSON object")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if settings.WANNetworks == nil {
		settings.WANNetworks = []string{}
	}
	current, err := h.getConfig(ctx)
	if err != nil {
		return nil, err
	}
	if current["sha256"] != expectedHash {
		return nil, errors.New("configuration changed since it was loaded; refresh before saving")
	}
	content, err := updateIntegrationConfig(current["content"].(string), settings)
	if err != nil {
		return nil, err
	}
	// Reuse the actual application validator, lock, post-lock hash comparison,
	// permissions and atomic rename. No service or generic UCI write is issued.
	response, err := h.saveConfig(ctx, content, expectedHash)
	if err != nil {
		return nil, err
	}
	response["content"], response["settings"] = content, settings
	response["path"], response["exists"] = current["path"], true
	return response, nil
}
