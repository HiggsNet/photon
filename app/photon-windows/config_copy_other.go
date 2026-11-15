//go:build !windows

package main

import (
	"github.com/HiggsNet/photon/internal/photonwindows/configedit"
	"io"
)

func elevatedConfigCopy(source, destination string) error {
	return configedit.Copy(source, destination)
}

func runConfigCopyWorker(_ []string, _ io.Writer) int { return 2 }
