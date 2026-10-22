package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
)

// Short reads are normal on a byte-stream transport; frame parsing must have
// the same bounded result regardless of where a pipe read is split.
type controlFuzzReader struct{ *bytes.Reader }

func (r controlFuzzReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func FuzzControlFrame(f *testing.F) {
	for _, seed := range [][]byte{nil, {0, 0, 0, 0}, {0, 0, 0, 1, 'x', 1}, {0, 0, 0, 2, 'x'}, {255, 255, 255, 255}, {0, 0, 16, 1}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > controlMaxRequest+32 {
			t.Skip()
		}
		before := bytes.Clone(wire)
		reader := bytes.NewReader(wire)
		body, err := readControlFrame(controlFuzzReader{reader}, controlMaxRequest)
		if !bytes.Equal(wire, before) {
			t.Fatal("frame parser changed input")
		}
		valid := false
		var size uint32
		if len(wire) >= 4 {
			size = binary.BigEndian.Uint32(wire[:4])
			valid = size > 0 && size <= controlMaxRequest && uint64(size) <= uint64(len(wire)-4)
		}
		if (err == nil) != valid {
			t.Fatalf("frame acceptance does not match bounded length: size=%d input=%d error=%v", size, len(wire), err)
		}
		if !valid {
			return
		}
		if !bytes.Equal(body, wire[4:4+int(size)]) || reader.Len() != len(wire)-4-int(size) {
			t.Fatal("frame crossed its advertised boundary")
		}
		var encoded bytes.Buffer
		if err := writeControlFrame(&encoded, body); err != nil || !bytes.Equal(encoded.Bytes(), wire[:4+int(size)]) {
			t.Fatal("accepted frame did not preserve body bytes")
		}
		if len(body) > 0 {
			body[0] ^= 1
			if !bytes.Equal(wire, before) {
				t.Fatal("frame result aliases input")
			}
		}
	})
}

type controlFuzzStream struct {
	io.Reader
	output bytes.Buffer
}

func (s *controlFuzzStream) Write(p []byte) (int, error) { return s.output.Write(p) }

func FuzzControlRequestDispatch(f *testing.F) {
	for _, seed := range []string{
		`{"version":1,"method":"status"}`, `{"version":1,"method":"peers"}`, `{"version":1,"method":"routes"}`, `{"version":1,"method":"diagnostics"}`, `{"version":1,"method":"stop"}`,
		`{"version":1,"method":"status","method":"stop"}`, `{"version":1,"version":2,"method":"stop"}`,
		`{"version":1,"method":"stop","config":{"private_key":"not-a-key"}}`,
		`{"version":1,"method":"status"}{}`, `{"version":1.0,"method":"status"}`, `{"version":null,"method":"stop"}`,
		`{"version":1,"\u006dethod":"stop"}`, `{"version":1,"method":"status","\u006dethod":"stop"}`, `null`, `[]`, "",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > controlMaxRequest {
			t.Skip()
		}
		before := bytes.Clone(body)
		method, parseErr := decodeControlRequest(body)
		if !bytes.Equal(body, before) {
			t.Fatal("JSON parser changed input")
		}
		if parseErr == nil {
			// Independently check the accepted shape using the standard JSON decoder,
			// then poison a canonical accepted request with a duplicate recognized key.
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil || len(fields) != 2 {
				t.Fatal("accepted unexpected request shape")
			}
			var version int
			var decodedMethod string
			if json.Unmarshal(fields["version"], &version) != nil || version != ControlVersion || json.Unmarshal(fields["method"], &decodedMethod) != nil || decodedMethod != method {
				t.Fatal("accepted unexpected field type")
			}
			canonical, _ := json.Marshal(map[string]any{"version": version, "method": method})
			poisoned := append(bytes.Clone(canonical[:len(canonical)-1]), []byte(`,"method":"stop"}`)...)
			if _, err := decodeControlRequest(poisoned); err == nil {
				t.Fatal("duplicate method authorized dispatch")
			}
		}
		var framed bytes.Buffer
		if len(body) == 0 {
			framed.Write([]byte{0, 0, 0, 0})
		} else if err := writeControlFrame(&framed, body); err != nil {
			t.Fatal(err)
		}
		framed.WriteByte(1) // completion acknowledgement, never another request
		stream := &controlFuzzStream{Reader: controlFuzzReader{bytes.NewReader(framed.Bytes())}}
		daemon := &controlTestDaemon{}
		err := serveControlRequest(context.Background(), stream, daemon)
		if parseErr != nil {
			if daemon.observed.Load() != 0 || daemon.stopped.Load() {
				t.Fatal("invalid request reached daemon owner")
			}
		} else if method == "stop" {
			if !daemon.stopped.Load() || daemon.observed.Load() != 0 {
				t.Fatal("stop did not dispatch exactly to shutdown")
			}
		} else if daemon.stopped.Load() || daemon.observed.Load() != 1 {
			t.Fatal("read-only request mutated owner or dispatched twice")
		}
		if len(body) == 0 {
			if err == nil {
				t.Fatal("empty frame accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		responseBody, err := readControlFrame(&stream.output, controlMaxFrame)
		if err != nil {
			t.Fatal(err)
		}
		var response ControlResponse
		if err := json.Unmarshal(responseBody, &response); err != nil || response.Version != ControlVersion {
			t.Fatal("invalid response frame")
		}
		if parseErr != nil {
			if response.Error == nil || response.Error.Code != "invalid_request" {
				t.Fatal("invalid request got success")
			}
		} else if response.Error != nil || response.Method != method {
			t.Fatal("valid request got wrong response")
		}
	})
}
