package main

import (
	"bytes"
	"testing"
)

func TestControlCommandsRequireConfigAndRejectExtraArguments(t *testing.T) {
	for _, method := range []string{"status", "peers", "routes", "diagnostics", "stop"} {
		for _, args := range [][]string{nil, {"--config", "unused", "extra"}, {"--unknown"}} {
			var stdout, stderr bytes.Buffer
			if code := runControl(method, args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("%s %v: code=%d out=%q err=%q", method, args, code, stdout.String(), stderr.String())
			}
		}
	}
}
