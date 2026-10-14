package gossip

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/vmihailenco/msgpack/v5"
)

// ObjectPullRequestType defines the kind of object being requested.
type ObjectPullRequestType string

const (
	ObjectPullZone   ObjectPullRequestType = "zone"
	ObjectPullRecord ObjectPullRequestType = "record"
)

// ObjectPullRequest is sent over TCP to request a zone snapshot or a single record.
type ObjectPullRequest struct {
	Type    ObjectPullRequestType `msgpack:"t"`
	Zone    zone.ZonePath         `msgpack:"z"`
	Key     string                `msgpack:"k,omitempty"`
	Version uint64                `msgpack:"v,omitempty"`
}

// ObjectPullResponse is returned by the TCP object-pull server.
type ObjectPullResponse struct {
	OK       bool                      `msgpack:"ok"`
	Snapshot *corestate.ZoneSnapshot   `msgpack:"s,omitempty"`
	Record   *corestate.RecordSnapshot `msgpack:"r,omitempty"`
	Error    string                    `msgpack:"e,omitempty"`
}

// ObjectPullSource returns detached objects from one committed common store.
// It exposes neither the complete network nor platform runtime state.
type ObjectPullSource interface {
	ReadZoneSnapshot(zone.ZonePath, time.Time) (*corestate.ZoneSnapshot, bool, error)
	ReadRecordSnapshot(zone.ZonePath, string, uint64) (*corestate.RecordSnapshot, error)
}

// BuildObjectPullResponse resolves the wire request using only the requested
// verified object. Zone snapshots retain their time-dependent revocation check.
func BuildObjectPullResponse(source ObjectPullSource, req *ObjectPullRequest, now time.Time) *ObjectPullResponse {
	if source == nil || req == nil || !req.Zone.Valid() {
		return &ObjectPullResponse{Error: "invalid request"}
	}
	switch req.Type {
	case ObjectPullZone:
		snapshot, revoked, err := source.ReadZoneSnapshot(req.Zone, now)
		if revoked {
			return &ObjectPullResponse{Error: "zone revoked"}
		}
		if err != nil {
			return &ObjectPullResponse{Error: err.Error()}
		}
		return &ObjectPullResponse{OK: true, Snapshot: snapshot}
	case ObjectPullRecord:
		if req.Key == "" {
			return &ObjectPullResponse{Error: "missing key"}
		}
		record, err := source.ReadRecordSnapshot(req.Zone, req.Key, req.Version)
		if err != nil {
			return &ObjectPullResponse{Error: err.Error()}
		}
		return &ObjectPullResponse{OK: true, Record: record}
	default:
		return &ObjectPullResponse{Error: "unsupported request type"}
	}
}

// ExchangeObjectPull performs the platform-neutral request/response exchange
// on an already connected stream. Dialing, deadlines and socket ownership stay
// with the injected platform transport.
func ExchangeObjectPull(stream io.ReadWriter, req *ObjectPullRequest) (*ObjectPullResponse, error) {
	if stream == nil {
		return nil, fmt.Errorf("object pull stream is nil")
	}
	data, err := EncodeObjectPullRequest(req)
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write(data); err != nil {
		return nil, err
	}
	return DecodeObjectPullResponse(stream)
}

// ServeObjectPull performs one platform-neutral server exchange on an already
// accepted stream. Listener ownership, admission limits and deadlines remain
// with the platform transport.
func ServeObjectPull(stream io.ReadWriter, lookup func(*ObjectPullRequest) *ObjectPullResponse) error {
	if stream == nil {
		return fmt.Errorf("object pull stream is nil")
	}
	request, err := DecodeObjectPullRequest(stream)
	if err != nil {
		return err
	}
	var response *ObjectPullResponse
	if lookup != nil {
		response = lookup(request)
	}
	if response == nil {
		response = &ObjectPullResponse{Error: "not found"}
	}
	data, err := EncodeObjectPullResponse(response)
	if err != nil {
		return err
	}
	_, err = stream.Write(data)
	return err
}

// EncodeObjectPullRequest serializes a request with a 4-byte big-endian length prefix.
func EncodeObjectPullRequest(req *ObjectPullRequest) ([]byte, error) {
	payload, err := msgpack.Marshal(req)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

// DecodeObjectPullRequest reads a length-prefixed request from r.
func DecodeObjectPullRequest(r io.Reader) (*ObjectPullRequest, error) {
	payload, err := readLengthPrefixed(r, 1<<20) // 1 MiB max request
	if err != nil {
		return nil, err
	}
	var req ObjectPullRequest
	if err := msgpack.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// EncodeObjectPullResponse serializes a response with a 4-byte big-endian length prefix.
func EncodeObjectPullResponse(resp *ObjectPullResponse) ([]byte, error) {
	payload, err := msgpack.Marshal(resp)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

// DecodeObjectPullResponse reads a length-prefixed response from r.
func DecodeObjectPullResponse(r io.Reader) (*ObjectPullResponse, error) {
	payload, err := readLengthPrefixed(r, 8<<20) // 8 MiB max response
	if err != nil {
		return nil, err
	}
	var resp ObjectPullResponse
	if err := msgpack.Unmarshal(payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func EncodeZoneSnapshotObject(snapshot *corestate.ZoneSnapshot) ([]byte, error) {
	return msgpack.Marshal(snapshot)
}

func DecodeZoneSnapshotObject(data []byte) (*corestate.ZoneSnapshot, error) {
	var snapshot corestate.ZoneSnapshot
	if err := msgpack.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func readLengthPrefixed(r io.Reader, maxSize int) ([]byte, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(sizeBuf[:]))
	if size > maxSize {
		return nil, fmt.Errorf("object pull payload size %d exceeds max %d", size, maxSize)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
