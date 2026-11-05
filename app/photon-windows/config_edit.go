package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/HiggsNet/photon/internal/photonwindows/configedit"
)

type configEditReply struct {
	Form  *configedit.Form `json:"form,omitempty"`
	Saved bool             `json:"saved,omitempty"`
	Error string           `json:"error,omitempty"`
}

func runConfigEdit(args []string, input io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("photon-windows config edit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "absolute configuration path")
	create := flags.Bool("new", false, "require a new configuration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*path) {
		fmt.Fprintln(stderr, "Usage: photon-windows config edit --config <absolute path> [--new]")
		return 2
	}

	output := json.NewEncoder(stdout)
	editor := configedit.New(filepath.Clean(*path))
	form, err := editor.LoadForm()
	if err == nil && form.NewConfig != *create {
		err = errors.New("configuration existence changed; choose an existing file to edit or a new path to create")
	}
	if err != nil {
		_ = output.Encode(configEditReply{Error: err.Error()})
		return 1
	}
	if err := output.Encode(configEditReply{Form: &form}); err != nil {
		return 1
	}

	requests := bufio.NewScanner(input)
	requests.Buffer(make([]byte, 4096), 2<<20)
	for requests.Scan() {
		var edited configedit.Form
		decoder := json.NewDecoder(bytes.NewReader(requests.Bytes()))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&edited)
		if err == nil && decoder.Decode(new(any)) != io.EOF {
			err = errors.New("expected one configuration form")
		}
		if err == nil {
			err = editor.SaveForm(edited)
		}
		if err == nil {
			if output.Encode(configEditReply{Saved: true}) != nil {
				return 1
			}
			return 0
		}
		if output.Encode(configEditReply{Error: err.Error()}) != nil {
			return 1
		}
	}
	if err := requests.Err(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
