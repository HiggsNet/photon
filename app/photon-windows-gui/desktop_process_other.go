//go:build !windows

package main

import "os/exec"

func desktopConfigureCommand(*exec.Cmd) {}
