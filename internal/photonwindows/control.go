package photonwindows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const ControlVersion = 1
const controlMaxFrame = 1 << 20
const controlMaxRequest = 4096
const controlTimeout = 5 * time.Second

// ControlDaemon is the running composition owner, never another state reader.
type ControlDaemon interface {
	Observe(context.Context) (Observation, error)
	Stop(context.Context) error
}

type ControlResponse struct {
	Version int             `json:"version"`
	Method  string          `json:"method"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ControlError   `json:"error,omitempty"`
}

type ControlError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ControlError) Error() string { return e.Code + ": " + e.Message }

// ControlEndpoint has no identity material and does not open the state file.
// Windows paths are case insensitive; an absolute clean path is stable across
// console and service callers using the same configuration.
func ControlEndpoint(statePath string) (string, error) {
	if strings.TrimSpace(statePath) == "" {
		return "", errors.New("state path is required")
	}
	path, err := filepath.Abs(statePath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return fmt.Sprintf(`\\.\pipe\Photon.Control.v1.%x`, sum[:]), nil
}

func controlMethod(method string) bool {
	switch method {
	case "status", "peers", "routes", "diagnostics", "stop":
		return true
	}
	return false
}

func readControlFrame(r io.Reader, limit uint32) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > limit {
		return nil, errors.New("invalid control frame size")
	}
	body := make([]byte, size)
	_, err := io.ReadFull(r, body)
	return body, err
}

func writeControlFrame(w io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > controlMaxFrame {
		return errors.New("invalid control frame size")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	for _, part := range [][]byte{header[:], body} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}

// The two-field request deliberately has no payload, mutable config or raw
// record access. Reject duplicate keys as well as unknown fields and versions.
func decodeControlRequest(body []byte) (string, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return "", errors.New("request must be an object")
	}
	seen := map[string]bool{}
	var version int
	var method string
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return "", err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return "", errors.New("duplicate request field")
		}
		seen[name] = true
		switch name {
		case "version":
			err = d.Decode(&version)
		case "method":
			err = d.Decode(&method)
		default:
			return "", errors.New("unknown request field")
		}
		if err != nil {
			return "", err
		}
	}
	if _, err := d.Token(); err != nil {
		return "", err
	}
	if _, err := d.Token(); err != io.EOF {
		return "", errors.New("trailing request data")
	}
	if version != ControlVersion || !controlMethod(method) {
		return "", errors.New("unsupported control version or method")
	}
	return method, nil
}

func controlResult(ctx context.Context, daemon ControlDaemon, method string) ControlResponse {
	response := ControlResponse{Version: ControlVersion, Method: method}
	fail := func(code, message string) ControlResponse {
		response.Error = &ControlError{Code: code, Message: message}
		return response
	}
	if method == "stop" {
		if err := daemon.Stop(ctx); err != nil {
			return fail("stop_failed", "daemon shutdown did not complete")
		}
		response.Result = json.RawMessage(`{"stopped":true}`)
		return response
	}
	observation, err := daemon.Observe(ctx)
	if err != nil {
		return fail("unavailable", "daemon observation is unavailable")
	}
	var result any
	switch method {
	case "status", "diagnostics":
		result = observation
	case "peers":
		result = struct {
			Peers     []PeerObservation `json:"peers"`
			Truncated bool              `json:"truncated"`
		}{observation.Peers, observation.PeersTruncated}
	case "routes":
		result = struct {
			Routes    []RouteObservation `json:"routes"`
			Truncated bool               `json:"truncated"`
		}{observation.Babel.Routes, observation.RoutesTruncated}
	}
	response.Result, err = json.Marshal(result)
	if err != nil {
		return fail("unavailable", "daemon observation could not be encoded")
	}
	return response
}

func serveControlRequest(ctx context.Context, stream io.ReadWriter, daemon ControlDaemon) error {
	body, err := readControlFrame(stream, controlMaxRequest)
	if err != nil {
		return err
	}
	method, err := decodeControlRequest(body)
	var response ControlResponse
	if err != nil {
		response = ControlResponse{Version: ControlVersion, Error: &ControlError{Code: "invalid_request", Message: "expected a supported v1 control method"}}
	} else {
		response = controlResult(ctx, daemon, method)
	}
	body, err = json.Marshal(response)
	if err != nil {
		return err
	}
	if len(body) > controlMaxFrame {
		body, _ = json.Marshal(ControlResponse{Version: ControlVersion, Method: method, Error: &ControlError{Code: "response_too_large", Message: "observation exceeds control frame limit"}})
	}
	if err := writeControlFrame(stream, body); err != nil {
		return err
	}
	// DisconnectNamedPipe discards unread data. A bounded acknowledgement lets
	// stop wait for actual cleanup and still deliver its result before disconnect.
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil {
		return err
	}
	if ack[0] != 1 {
		return errors.New("invalid control acknowledgement")
	}
	return nil
}

func exchangeControl(stream io.ReadWriter, method string) (ControlResponse, error) {
	var response ControlResponse
	if !controlMethod(method) {
		return response, errors.New("unsupported control method")
	}
	request, _ := json.Marshal(struct {
		Version int    `json:"version"`
		Method  string `json:"method"`
	}{ControlVersion, method})
	if err := writeControlFrame(stream, request); err != nil {
		return response, err
	}
	body, err := readControlFrame(stream, controlMaxFrame)
	if err != nil {
		return response, err
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&response); err != nil {
		return response, err
	}
	if _, err := d.Token(); err != io.EOF {
		return response, errors.New("trailing control response")
	}
	if response.Version != ControlVersion || response.Method != method || (response.Error == nil) == (len(response.Result) == 0) {
		return response, errors.New("invalid control response envelope")
	}
	if _, err := stream.Write([]byte{1}); err != nil {
		return response, err
	}
	if response.Error != nil {
		return response, response.Error
	}
	return response, nil
}
