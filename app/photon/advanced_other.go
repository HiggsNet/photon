//go:build !linux

package main

import "github.com/urfave/cli/v3"

func platformAdvancedCommands() []*cli.Command { return nil }
