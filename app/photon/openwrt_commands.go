//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/HiggsNet/photon/internal/photonopenwrt"
	"github.com/urfave/cli/v3"
)

func cmdOpenWrtRefresh() *cli.Command {
	return &cli.Command{Name: "openwrt-refresh", Usage: "Refresh selected netifd WAN addresses and fw4 rules through the running daemon", Action: func(ctx context.Context, command *cli.Command) error {
		// Hotplug is an invalidation hint. It must never open the database or
		// create a second publisher when the service is stopped.
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		var response controlResponse
		if err := exchangeControl(ctx, controlSocketPath(nil), controlRequest{Method: "openwrt_refresh"}, &response); err != nil {
			return err
		}
		if !response.OK {
			return errors.New(response.Error)
		}
		return nil
	}}
}

func cmdOpenWrtCleanup() *cli.Command {
	return &cli.Command{Name: "openwrt-cleanup", Usage: "Withdraw only Photon-owned fw4 input rules after procd has stopped Photon", Action: func(ctx context.Context, command *cli.Command) error {
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "unix", controlSocketPath(nil))
		if err == nil {
			_ = conn.Close()
			return errors.New("Photon is still running; stop the managed daemon before OpenWrt cleanup")
		}
		if !isControlSocketUnavailable(err) {
			return err
		}
		return photonopenwrt.NewFirewall(photonopenwrt.FirewallOptions{}).Cleanup(ctx)
	}}
}
