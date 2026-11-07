//go:build !windows

package mihomoproxy

import "os/exec"

func configureCommand(*exec.Cmd) {}

func ownProcess(*exec.Cmd) (func(), error) { return nil, nil }
