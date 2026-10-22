package photonwindows

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWintunConflictRequiresLiveForeignIPInterface(t *testing.T) {
	owner := windows.GUID{Data1: 1}
	foreign := windows.MibIfRow2{InterfaceGuid: windows.GUID{Data1: 2}, InterfaceLuid: 10}
	alias, _ := windows.UTF16FromString("PhotonFixture")
	copy(foreign.Alias[:], alias)
	if foreignAliasPresent("photonfixture", owner, []windows.MibIfRow2{foreign}, nil) {
		t.Fatal("PnP tombstone classified as foreign owner")
	}
	active := map[uint64]bool{10: true}
	if !foreignAliasPresent("photonfixture", owner, []windows.MibIfRow2{foreign}, active) {
		t.Fatal("live case-insensitive alias collision ignored")
	}
	if foreignAliasPresent("other", owner, []windows.MibIfRow2{foreign}, active) {
		t.Fatal("unrelated alias classified as conflicting")
	}
	foreign.InterfaceGuid = owner
	if foreignAliasPresent("PhotonFixture", owner, []windows.MibIfRow2{foreign}, active) {
		t.Fatal("own GUID classified as foreign")
	}
}
