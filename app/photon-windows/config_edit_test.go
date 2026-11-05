package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigEditSessionCreatesConfigAfterCorrectingForm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "first run.yaml")
	input, request := io.Pipe()
	response, output := io.Pipe()
	t.Cleanup(func() {
		request.Close()
		response.Close()
	})
	done := make(chan int, 1)
	var stderr bytes.Buffer
	go func() {
		done <- runConfigEdit([]string{"--config", path, "--new"}, input, output, &stderr)
		output.Close()
		input.Close()
	}()
	decoder := json.NewDecoder(response)
	var opened configEditReply
	if err := decoder.Decode(&opened); err != nil || opened.Form == nil || !opened.Form.NewConfig {
		t.Fatalf("load: %+v, %v", opened, err)
	}
	encoder := json.NewEncoder(request)
	if err := encoder.Encode(opened.Form); err != nil {
		t.Fatal(err)
	}
	var rejected configEditReply
	if err := decoder.Decode(&rejected); err != nil || rejected.Error == "" {
		t.Fatalf("invalid form: %+v, %v", rejected, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid form touched config: %v", err)
	}
	opened.Form.RootPublicKey = strings.Repeat("01", 32)
	opened.Form.ManagedZone = "laptop.example."
	opened.Form.SplitRoutes = "fd42::/16"
	if err := encoder.Encode(opened.Form); err != nil {
		t.Fatal(err)
	}
	var saved configEditReply
	if err := decoder.Decode(&saved); err != nil || !saved.Saved {
		t.Fatalf("save: %+v, %v", saved, err)
	}
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(opened.Form.StatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configuration editor touched identity state: %v", err)
	}
}
