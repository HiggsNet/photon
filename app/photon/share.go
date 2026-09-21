package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/HiggsNet/photon/pkg/core/share"
)

func readBase64JSONOrJSON(input string, out any) error {
	if data, err := os.ReadFile(input); err == nil {
		if err := share.DecodeBase64JSON(string(data), out); err == nil {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s: %w", input, err)
		}
		return nil
	}
	if err := share.DecodeBase64JSON(input, out); err != nil {
		return fmt.Errorf("decode base64 JSON payload: %w", err)
	}
	return nil
}

func writeBase64JSONFile(path string, mode os.FileMode, value any) error {
	text, err := share.EncodeBase64JSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(text+"\n"), mode)
}

func readJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSONFile(path string, mode os.FileMode, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, mode)
}
