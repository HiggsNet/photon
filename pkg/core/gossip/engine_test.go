package gossip

import "testing"

func TestEngineOwnsSessions(t *testing.T) {
	engine := NewEngine()
	session := engine.NewSession("peer-a")
	if engine.Session("peer-a") != session || !engine.HasActiveSession("peer-a") {
		t.Fatal("engine did not retain active session")
	}
	engine.RemoveSession("peer-a")
	if engine.Session("peer-a") != nil {
		t.Fatal("session remains after RemoveSession")
	}
}

func TestEnginePendingHints(t *testing.T) {
	engine := NewEngine()
	engine.DeferHint("peer-a")
	if !engine.PendingHint("peer-a") || !engine.TakePendingHint("peer-a") || engine.PendingHint("peer-a") {
		t.Fatal("pending hint lifecycle failed")
	}
}
