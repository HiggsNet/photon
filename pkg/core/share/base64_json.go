// Package share implements the portable Base64 JSON format used by Photon
// join requests, join bundles and recovery exports.
package share

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func EncodeBase64JSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func DecodeBase64JSON(text string, out any) error {
	trimmed := strings.TrimSpace(text)
	var decodeErr error
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		data, err := encoding.DecodeString(trimmed)
		if err != nil {
			if decodeErr == nil {
				decodeErr = err
			}
			continue
		}
		if err := json.Unmarshal(data, out); err != nil {
			return err
		}
		return nil
	}
	return decodeErr
}
