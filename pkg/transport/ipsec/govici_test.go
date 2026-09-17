package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"
)

type fakeGoviciSession struct {
	callCmd      string
	callIn       map[string]any
	streamCmd    string
	streamEvent  string
	streamIn     map[string]any
	callOut      *vici.Message
	streamEvents []*vici.Message
	subscribed   []string
	eventCh      chan<- vici.Event
}

func (s *fakeGoviciSession) Call(_ context.Context, cmd string, in *vici.Message) (*vici.Message, error) {
	s.callCmd = cmd
	s.callIn = goviciMessageToMap(in)
	return s.callOut, nil
}

func (s *fakeGoviciSession) CallStreaming(_ context.Context, cmd string, event string, in *vici.Message) iter.Seq2[*vici.Message, error] {
	s.streamCmd = cmd
	s.streamEvent = event
	s.streamIn = goviciMessageToMap(in)
	return func(yield func(*vici.Message, error) bool) {
		for _, msg := range s.streamEvents {
			if !yield(msg, nil) {
				return
			}
		}
	}
}

func (s *fakeGoviciSession) Close() error {
	return nil
}

func (s *fakeGoviciSession) Subscribe(events ...string) error {
	s.subscribed = append(s.subscribed, events...)
	return nil
}

func (s *fakeGoviciSession) NotifyEvents(ch chan<- vici.Event) {
	s.eventCh = ch
}

func (s *fakeGoviciSession) StopEvents(ch chan<- vici.Event) {
	if s.eventCh == ch {
		s.eventCh = nil
	}
}

type blockingGoviciSession struct{}

func (s blockingGoviciSession) Call(ctx context.Context, _ string, _ *vici.Message) (*vici.Message, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s blockingGoviciSession) CallStreaming(ctx context.Context, _ string, _ string, _ *vici.Message) iter.Seq2[*vici.Message, error] {
	return func(yield func(*vici.Message, error) bool) {
		<-ctx.Done()
		yield(nil, ctx.Err())
	}
}

func (s blockingGoviciSession) Close() error {
	return nil
}

// wedgedGoviciEventSession models a VICI daemon that accepts the connection
// but never confirms the event registration: Subscribe blocks until the
// session is closed.
type wedgedGoviciEventSession struct {
	closeCh  chan struct{}
	closeOne sync.Once
}

func newWedgedGoviciEventSession() *wedgedGoviciEventSession {
	return &wedgedGoviciEventSession{closeCh: make(chan struct{})}
}

func (s *wedgedGoviciEventSession) Call(context.Context, string, *vici.Message) (*vici.Message, error) {
	return nil, errors.New("wedged session")
}

func (s *wedgedGoviciEventSession) CallStreaming(context.Context, string, string, *vici.Message) iter.Seq2[*vici.Message, error] {
	return func(yield func(*vici.Message, error) bool) {
		yield(nil, errors.New("wedged session"))
	}
}

func (s *wedgedGoviciEventSession) Close() error {
	s.closeOne.Do(func() { close(s.closeCh) })
	return nil
}

func (s *wedgedGoviciEventSession) Subscribe(events ...string) error {
	<-s.closeCh
	return errors.New("session closed while subscribing")
}

func (s *wedgedGoviciEventSession) NotifyEvents(chan<- vici.Event) {}

func (s *wedgedGoviciEventSession) StopEvents(chan<- vici.Event) {}

type blockingVICIClient struct {
	calls   chan string
	release chan struct{}
}

func (c *blockingVICIClient) Call(ctx context.Context, cmd string, _ map[string]any) (map[string]any, error) {
	select {
	case c.calls <- cmd:
	default:
	}
	select {
	case <-c.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *blockingVICIClient) CallStreaming(context.Context, string, string, map[string]any) ([]map[string]any, error) {
	return nil, nil
}

type controlledInitiateCall struct {
	child   string
	timeout string
}

type controlledInitiateClient struct {
	started  chan controlledInitiateCall
	release  chan struct{}
	finished chan error

	mu        sync.Mutex
	active    int
	maxActive int
}

func newControlledInitiateClient(size int) *controlledInitiateClient {
	return &controlledInitiateClient{
		started:  make(chan controlledInitiateCall, size),
		release:  make(chan struct{}, size),
		finished: make(chan error, size),
	}
}

func (c *controlledInitiateClient) Call(ctx context.Context, cmd string, in map[string]any) (map[string]any, error) {
	if cmd != "initiate" {
		return nil, fmt.Errorf("unexpected command %q", cmd)
	}
	call := controlledInitiateCall{
		child:   fmt.Sprint(in["child"]),
		timeout: fmt.Sprint(in["timeout"]),
	}
	c.mu.Lock()
	c.active++
	if c.active > c.maxActive {
		c.maxActive = c.active
	}
	c.mu.Unlock()
	c.started <- call

	var err error
	select {
	case <-c.release:
	case <-ctx.Done():
		err = ctx.Err()
	}
	c.mu.Lock()
	c.active--
	c.mu.Unlock()
	c.finished <- err
	return nil, err
}

func (c *controlledInitiateClient) CallStreaming(context.Context, string, string, map[string]any) ([]map[string]any, error) {
	return nil, nil
}

func (c *controlledInitiateClient) peakActive() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxActive
}

type scriptedVICIClient struct {
	callErr   error
	streamOut []map[string]any
	streamErr error
}

func (c *scriptedVICIClient) Call(context.Context, string, map[string]any) (map[string]any, error) {
	if c.callErr != nil {
		return nil, c.callErr
	}
	return nil, nil
}

func (c *scriptedVICIClient) CallStreaming(context.Context, string, string, map[string]any) ([]map[string]any, error) {
	if c.streamErr != nil {
		return nil, c.streamErr
	}
	return c.streamOut, nil
}

func TestGoviciClientMarshalsLoadConnectionMessage(t *testing.T) {
	session := &fakeGoviciSession{}
	client := &GoviciClient{Session: session}
	spec := sampleStrongSwanSpec()

	if err := (&StrongSwanDriver{VICI: client}).LoadConnection(context.Background(), spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}
	if session.callCmd != "load-conn" {
		t.Fatalf("cmd = %q, want load-conn", session.callCmd)
	}
	conn, ok := session.callIn[spec.TransportID].(map[string]any)
	if !ok {
		t.Fatalf("connection missing from call input: %#v", session.callIn)
	}
	if conn["version"] != "2" || conn["remote_port"] != "4500" || conn["encap"] != "yes" || conn["mobike"] != "no" || conn["unique"] != "never" {
		t.Fatalf("connection scalar fields = %#v", conn)
	}
	children, ok := conn["children"].(map[string]any)
	if !ok {
		t.Fatalf("children = %#v", conn["children"])
	}
	child, ok := children[ChildSAName(spec)].(map[string]any)
	if !ok {
		t.Fatalf("child missing from children: %#v", children)
	}
	if child["if_id_in"] != "77" || child["if_id_out"] != "77" {
		t.Fatalf("child if_id fields = %#v", child)
	}
	if child["start_action"] != "none" {
		t.Fatalf("child start_action = %#v, want none", child["start_action"])
	}
}

func TestStrongSwanDriverMarshalsInitiateServerTimeout(t *testing.T) {
	session := &fakeGoviciSession{}
	client := &GoviciClient{Session: session}
	driver := &StrongSwanDriver{
		VICI:            client,
		InitiateTimeout: 1250 * time.Millisecond,
	}

	if err := driver.InitiateChild(context.Background(), "ipsec-main-child"); err != nil {
		t.Fatalf("InitiateChild: %v", err)
	}
	if session.callCmd != "initiate" {
		t.Fatalf("command = %q, want initiate", session.callCmd)
	}
	if child := session.callIn["child"]; child != "ipsec-main-child" {
		t.Fatalf("child = %#v, want ipsec-main-child", child)
	}
	if timeout := session.callIn["timeout"]; timeout != "1250" {
		t.Fatalf("timeout = %#v, want 1250ms", timeout)
	}
}

func TestStrongSwanDriverTerminatesByUniqueID(t *testing.T) {
	session := &fakeGoviciSession{}
	driver := &StrongSwanDriver{VICI: &GoviciClient{Session: session}}
	if err := driver.TerminateSAByID(context.Background(), 42); err != nil {
		t.Fatalf("TerminateSAByID: %v", err)
	}
	if session.callCmd != "terminate" || session.callIn["ike-id"] != "42" || session.callIn["force"] != "yes" {
		t.Fatalf("terminate request = %s %#v", session.callCmd, session.callIn)
	}
}

func TestStrongSwanDriverBoundsVICIOperation(t *testing.T) {
	client := &GoviciClient{Session: blockingGoviciSession{}}
	driver := &StrongSwanDriver{
		VICI:             client,
		OperationTimeout: 10 * time.Millisecond,
	}

	start := time.Now()
	err := driver.LoadConnection(context.Background(), sampleStrongSwanSpec())
	if err == nil {
		t.Fatal("LoadConnection error = nil, want timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("LoadConnection took too long: %s", time.Since(start))
	}
	if !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("LoadConnection error = %v, want deadline exceeded", err)
	}
}

func TestStrongSwanDriverInitiateChildAsyncReturnsAndCoalesces(t *testing.T) {
	client := &blockingVICIClient{
		calls:   make(chan string, 2),
		release: make(chan struct{}),
	}
	driver := &StrongSwanDriver{
		VICI:          client,
		InitiateAsync: true,
	}

	start := time.Now()
	if err := driver.InitiateChild(context.Background(), "ipsec-main-child"); err != nil {
		t.Fatalf("InitiateChild: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("InitiateChild blocked for %s", time.Since(start))
	}
	if err := driver.InitiateChild(context.Background(), "ipsec-main-child"); err != nil {
		t.Fatalf("second InitiateChild: %v", err)
	}
	select {
	case cmd := <-client.calls:
		if cmd != "initiate" {
			t.Fatalf("command = %q, want initiate", cmd)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for async initiate call")
	}
	select {
	case cmd := <-client.calls:
		t.Fatalf("unexpected duplicate async call %q", cmd)
	case <-time.After(20 * time.Millisecond):
	}
	close(client.release)
}

func TestStrongSwanDriverAsyncInitiateUsesServerTimeoutAndOutlivesReconcileContext(t *testing.T) {
	client := newControlledInitiateClient(1)
	driver := &StrongSwanDriver{
		VICI:                  client,
		InitiateAsync:         true,
		InitiateClientTimeout: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := driver.InitiateChild(ctx, "ipsec-main-child"); err != nil {
		t.Fatalf("InitiateChild: %v", err)
	}
	// This models flushIPsecReconcile returning and canceling its bounded
	// context immediately after the detached initiate was scheduled.
	cancel()

	select {
	case call := <-client.started:
		if call.child != "ipsec-main-child" {
			t.Fatalf("child = %q, want ipsec-main-child", call.child)
		}
		if call.timeout != "15000" {
			t.Fatalf("server timeout = %q, want 15000ms", call.timeout)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for async initiate call")
	}
	select {
	case err := <-client.finished:
		t.Fatalf("async initiate inherited reconcile cancellation: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	client.release <- struct{}{}
	select {
	case err := <-client.finished:
		if err != nil {
			t.Fatalf("async initiate error after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for async initiate completion")
	}
}

func TestStrongSwanDriverLimitsConcurrentAsyncInitiates(t *testing.T) {
	const (
		concurrency = defaultVICIInitiateConcurrency
		callCount   = concurrency + 3
	)
	client := newControlledInitiateClient(callCount)
	driver := &StrongSwanDriver{
		VICI:                  client,
		InitiateAsync:         true,
		InitiateClientTimeout: time.Second,
	}
	for i := range callCount {
		child := fmt.Sprintf("ipsec-child-%d", i)
		if err := driver.InitiateChild(context.Background(), child); err != nil {
			t.Fatalf("InitiateChild(%q): %v", child, err)
		}
	}

	for i := range concurrency {
		select {
		case <-client.started:
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for initial call %d", i)
		}
	}
	select {
	case call := <-client.started:
		t.Fatalf("initiate beyond concurrency limit started before a slot was released: %+v", call)
	case <-time.After(30 * time.Millisecond):
	}

	client.release <- struct{}{}
	select {
	case <-client.started:
	case <-time.After(time.Second):
		t.Fatal("queued initiate did not start after a slot was released")
	}
	for i := 1; i < callCount; i++ {
		client.release <- struct{}{}
	}
	for i := range callCount {
		select {
		case err := <-client.finished:
			if err != nil {
				t.Fatalf("async initiate %d failed: %v", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for async initiate %d", i)
		}
	}
	if got := client.peakActive(); got > concurrency {
		t.Fatalf("peak concurrent initiates = %d, want <= %d", got, concurrency)
	}
}

func TestReconnectingVICIClientRetriesStreamingAfterBrokenPipe(t *testing.T) {
	closed := 0
	factoryCalls := 0
	client, err := NewReconnectingVICIClient(func() (VICIClient, func() error, error) {
		factoryCalls++
		if factoryCalls == 1 {
			return &scriptedVICIClient{streamErr: errors.New("write unix @->/run/charon.vici: write: broken pipe")}, func() error {
				closed++
				return nil
			}, nil
		}
		return &scriptedVICIClient{streamOut: []map[string]any{{"ipsec-main-ab": map[string]any{"state": "ESTABLISHED"}}}}, func() error {
			closed++
			return nil
		}, nil
	})
	if err != nil {
		t.Fatalf("NewReconnectingVICIClient: %v", err)
	}

	events, err := client.CallStreaming(context.Background(), "list-sas", "list-sa", nil)
	if err != nil {
		t.Fatalf("CallStreaming: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one event after reconnect", events)
	}
	if factoryCalls != 2 {
		t.Fatalf("factory calls = %d, want 2", factoryCalls)
	}
	if closed != 1 {
		t.Fatalf("closed = %d, want stale client closed once", closed)
	}
}

func TestReconnectingVICIClientInvalidatesStreamingSessionAfterDeadline(t *testing.T) {
	closed := 0
	factoryCalls := 0
	client, err := NewReconnectingVICIClient(func() (VICIClient, func() error, error) {
		factoryCalls++
		if factoryCalls == 1 {
			return &scriptedVICIClient{streamErr: context.DeadlineExceeded}, func() error {
				closed++
				return nil
			}, nil
		}
		return &scriptedVICIClient{streamOut: []map[string]any{{"ipsec-main-ab": map[string]any{"state": "ESTABLISHED"}}}}, func() error {
			closed++
			return nil
		}, nil
	})
	if err != nil {
		t.Fatalf("NewReconnectingVICIClient: %v", err)
	}

	if _, err := client.CallStreaming(context.Background(), "list-sas", "list-sa", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first CallStreaming error = %v, want deadline exceeded", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("factory calls after timeout = %d, want lazy reconnect", factoryCalls)
	}
	if closed != 1 {
		t.Fatalf("closed after timeout = %d, want stale session closed", closed)
	}

	events, err := client.CallStreaming(context.Background(), "list-sas", "list-sa", nil)
	if err != nil {
		t.Fatalf("second CallStreaming: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one event from fresh session", events)
	}
	if factoryCalls != 2 {
		t.Fatalf("factory calls = %d, want fresh session on next call", factoryCalls)
	}
}

func TestReconnectingVICIClientUsesDedicatedLifecycleSession(t *testing.T) {
	commandSession := &fakeGoviciSession{}
	eventSession := &fakeGoviciSession{}
	factoryCalls := 0
	commandClosed := 0
	eventClosed := 0
	client, err := NewReconnectingVICIClient(func() (VICIClient, func() error, error) {
		factoryCalls++
		switch factoryCalls {
		case 1:
			return &GoviciClient{Session: commandSession}, func() error {
				commandClosed++
				return nil
			}, nil
		case 2:
			return &GoviciClient{Session: eventSession}, func() error {
				eventClosed++
				return nil
			}, nil
		default:
			return nil, nil, fmt.Errorf("unexpected factory call %d", factoryCalls)
		}
	})
	if err != nil {
		t.Fatalf("NewReconnectingVICIClient: %v", err)
	}

	_, stop, err := client.SubscribeEvents(context.Background(), "child-updown", "ike-updown")
	if err != nil {
		t.Fatalf("SubscribeEvents: %v", err)
	}
	if !reflect.DeepEqual(eventSession.subscribed, []string{"child-updown", "ike-updown"}) {
		t.Fatalf("event session subscriptions = %+v", eventSession.subscribed)
	}
	if len(commandSession.subscribed) != 0 {
		t.Fatalf("command session unexpectedly subscribed to events: %+v", commandSession.subscribed)
	}
	if _, err := client.CallStreaming(context.Background(), "list-sas", "list-sa", nil); err != nil {
		t.Fatalf("CallStreaming: %v", err)
	}
	if commandSession.streamCmd != "list-sas" {
		t.Fatalf("command session stream command = %q, want list-sas", commandSession.streamCmd)
	}

	stop()
	stop()
	if eventClosed != 1 {
		t.Fatalf("event session closed = %d, want once", eventClosed)
	}
	if commandClosed != 0 {
		t.Fatalf("command session closed with subscription = %d", commandClosed)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if commandClosed != 1 {
		t.Fatalf("command session closed = %d, want once", commandClosed)
	}
}

func TestReconnectingVICIClientRecoversAfterReconnectDialFailure(t *testing.T) {
	closed := 0
	factoryCalls := 0
	client, err := NewReconnectingVICIClient(func() (VICIClient, func() error, error) {
		factoryCalls++
		switch factoryCalls {
		case 1:
			return &scriptedVICIClient{streamErr: errors.New("read unix @->/run/charon.vici: connection reset by peer")}, func() error {
				closed++
				return nil
			}, nil
		case 2:
			return nil, nil, errors.New("dial unix /run/charon.vici: connect: connection refused")
		default:
			return &scriptedVICIClient{streamOut: []map[string]any{{"ipsec-main-ab": map[string]any{"state": "ESTABLISHED"}}}}, func() error {
				closed++
				return nil
			}, nil
		}
	})
	if err != nil {
		t.Fatalf("NewReconnectingVICIClient: %v", err)
	}

	if _, err := client.CallStreaming(context.Background(), "list-sas", "list-sa", nil); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("first CallStreaming error = %v, want reconnect dial failure", err)
	}
	events, err := client.CallStreaming(context.Background(), "list-sas", "list-sa", nil)
	if err != nil {
		t.Fatalf("second CallStreaming: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one event after VICI becomes available", events)
	}
	if factoryCalls != 3 {
		t.Fatalf("factory calls = %d, want initial dial, failed redial, and successful redial", factoryCalls)
	}
	if closed != 1 {
		t.Fatalf("closed = %d, want stale client closed once", closed)
	}
}

func TestStrongSwanDriverLogsVICILoadConnectionConfig(t *testing.T) {
	session := &fakeGoviciSession{}
	client := &GoviciClient{Session: session}
	spec := sampleStrongSwanSpec()
	var gotEvent string
	var gotFields map[string]any
	driver := &StrongSwanDriver{
		VICI: client,
		LogConfig: func(event string, fields map[string]any) {
			gotEvent = event
			gotFields = fields
		},
	}

	if err := driver.LoadConnection(context.Background(), spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}
	if gotEvent != "vici_load_conn" {
		t.Fatalf("event = %q, want vici_load_conn", gotEvent)
	}
	if gotFields["connection"] != spec.TransportID || gotFields["command"] != "load-conn" {
		t.Fatalf("fields = %+v", gotFields)
	}
	configJSON, ok := gotFields["config_json"].(string)
	if !ok || configJSON == "" {
		t.Fatalf("config_json = %#v", gotFields["config_json"])
	}
	for _, want := range []string{spec.TransportID, `"remote_port":"4500"`, `"encap":"yes"`, `"mobike":"no"`, `"unique":"never"`, ChildSAName(spec)} {
		if !strings.Contains(configJSON, want) {
			t.Fatalf("config_json missing %q: %s", want, configJSON)
		}
	}
}

func TestSanitizeVICIConfigForLogRedactsKeyMaterial(t *testing.T) {
	sanitized := sanitizeVICIConfigForLog(map[string]any{
		"conn": map[string]any{
			"local": map[string]any{
				"pubkeys": []string{"-----BEGIN PUBLIC KEY-----\nsecret-ish\n-----END PUBLIC KEY-----"},
			},
			"remote": map[string]any{
				"data": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
			},
		},
	}).(map[string]any)
	data, err := json.Marshal(sanitized)
	if err != nil {
		t.Fatalf("Marshal sanitized config: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "BEGIN") || strings.Contains(text, "secret") {
		t.Fatalf("sanitized config leaked key material: %#v", sanitized)
	}
	conn := sanitized["conn"].(map[string]any)
	local := conn["local"].(map[string]any)
	remote := conn["remote"].(map[string]any)
	if local["pubkeys"] != "present:1" || remote["data"] != "present" {
		t.Fatalf("sanitized config = %#v", sanitized)
	}
}

func TestGoviciClientStreamsListSAs(t *testing.T) {
	event, err := vici.MarshalMessage(map[string]any{
		"ipsec-main-ab": map[string]any{
			"local-host":  "198.51.100.10",
			"local-port":  "4500",
			"local-id":    "node-a.catofes.",
			"remote-host": "198.51.100.20",
			"remote-port": "4500",
			"remote-id":   "node-b.catofes.",
			"state":       "ESTABLISHED",
			"child-sas": map[string]any{
				"ipsec-main-ab-child": map[string]any{
					"reqid":     "17",
					"if-id-out": "4d",
					"state":     "INSTALLED",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	session := &fakeGoviciSession{streamEvents: []*vici.Message{event}}
	client := &GoviciClient{Session: session}

	states, err := (&StrongSwanDriver{VICI: client}).ListSAs(context.Background())
	if err != nil {
		t.Fatalf("ListSAs: %v", err)
	}
	if session.streamCmd != "list-sas" || session.streamEvent != "list-sa" {
		t.Fatalf("stream command = %q/%q", session.streamCmd, session.streamEvent)
	}
	want := []SAState{{
		Name:           "ipsec-main-ab",
		Peer:           "198.51.100.20",
		ChildSA:        "ipsec-main-ab-child",
		IKEState:       "ESTABLISHED",
		ChildState:     "INSTALLED",
		XFRMIfID:       77,
		ReqID:          17,
		LocalIdentity:  "node-a.catofes.",
		RemoteIdentity: "node-b.catofes.",
		LocalEndpoint:  "198.51.100.10:4500",
		RemoteEndpoint: "198.51.100.20:4500",
		Endpoint:       "198.51.100.20:4500",
		Established:    true,
	}}
	if !reflect.DeepEqual(states, want) {
		t.Fatalf("states:\n got %#v\nwant %#v", states, want)
	}
}

func TestGoviciClientStreamsListConnections(t *testing.T) {
	event, err := vici.MarshalMessage(map[string]any{
		"ipsec-main-ab": map[string]any{
			"remote_addrs": []string{"198.51.100.20"},
			"remote_port":  "4500",
			"local": map[string]any{
				"id": "node-a.catofes.",
			},
			"remote": map[string]any{
				"id": "node-b.catofes.",
			},
		},
	})
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	session := &fakeGoviciSession{streamEvents: []*vici.Message{event}}
	client := &GoviciClient{Session: session}

	states, err := (&StrongSwanDriver{VICI: client}).ListConnections(context.Background())
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	if session.streamCmd != "list-conns" || session.streamEvent != "list-conn" {
		t.Fatalf("stream command = %q/%q", session.streamCmd, session.streamEvent)
	}
	want := []ConnectionState{{
		Name:           "ipsec-main-ab",
		LocalIdentity:  "node-a.catofes.",
		RemoteIdentity: "node-b.catofes.",
		RemoteEndpoint: "198.51.100.20:4500",
	}}
	if !reflect.DeepEqual(states, want) {
		t.Fatalf("states:\n got %#v\nwant %#v", states, want)
	}
}

func TestGoviciClientSubscribesAndParsesLifecycleEvents(t *testing.T) {
	session := &fakeGoviciSession{}
	client := &GoviciClient{Session: session}
	events, stop, err := client.SubscribeEvents(context.Background(), "child-updown", "ike-updown")
	if err != nil {
		t.Fatalf("SubscribeEvents: %v", err)
	}
	defer stop()
	if !reflect.DeepEqual(session.subscribed, []string{"child-updown", "ike-updown"}) {
		t.Fatalf("subscribed = %+v", session.subscribed)
	}
	msg, err := vici.MarshalMessage(map[string]any{
		"ike":         "ipsec-main-ab",
		"child":       "ipsec-main-ab-child{2}",
		"up":          "yes",
		"if_id_out":   "77",
		"reqid":       "17",
		"local-id":    "node-a.catofes.",
		"remote-id":   "node-b.catofes.",
		"local-host":  "198.51.100.10",
		"local-port":  "4500",
		"remote-host": "198.51.100.20",
		"remote-port": "4500",
	})
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	session.eventCh <- vici.Event{Name: "child-updown", Message: msg}
	select {
	case ev := <-events:
		if ev.Name != "child-updown" || ev.Connection != "ipsec-main-ab" || ev.ChildSA != "ipsec-main-ab-child" || !ev.Up {
			t.Fatalf("event = %+v", ev)
		}
		if ev.XFRMIfID != 77 || ev.ReqID != 17 || ev.RemoteEndpoint != "198.51.100.20:4500" {
			t.Fatalf("event numeric/endpoint fields = %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for lifecycle event")
	}
}

func TestGoviciClientSubscribeEventsUnblocksOnContextTimeout(t *testing.T) {
	// A VICI daemon that accepts the connection but never confirms the event
	// registration must not block the caller forever: the ctx deadline closes
	// the session and surfaces the timeout.
	session := newWedgedGoviciEventSession()
	client := &GoviciClient{Session: session}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := client.SubscribeEvents(ctx, "child-updown")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SubscribeEvents error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("SubscribeEvents blocked for %s despite the ctx deadline", elapsed)
	}
}

func sampleStrongSwanSpec() TransportLinkSpec {
	return TransportLinkSpec{
		TransportID:   "ipsec-main-ab",
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		InterfaceName: "phxab0",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:  "198.51.100.20",
			IKEPort:  4500,
			NATTPort: 4500,
		}},
	}
}
