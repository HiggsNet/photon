package main

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
	"github.com/urfave/cli/v3"
)

func TestServicePublishCLIKeepsCommaDelimitedEndpointsIntact(t *testing.T) {
	service := cmdService()
	publish := commandByName(service.Commands, "publish")
	if publish == nil {
		t.Fatal("publish command is missing")
	}
	var got []string
	publish.Action = func(_ context.Context, cmd *cli.Command) error {
		got = cmd.StringSlice("endpoint")
		return nil
	}
	root := &cli.Command{Name: "photon", Commands: []*cli.Command{service}}
	args := []string{
		"photon", "service", "publish",
		"--endpoint", "local,2a0d:2905:1:4::20,3128",
		"--endpoint", "cn,2a0d:2905:1:5::20,3128",
	}
	if err := root.Run(context.Background(), args); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"local,2a0d:2905:1:4::20,3128", "cn,2a0d:2905:1:5::20,3128"}
	if !slices.Equal(got, want) {
		t.Fatalf("endpoint flags = %#v, want %#v", got, want)
	}
}

func TestServiceCLIExposesTableAndLocalViews(t *testing.T) {
	service := cmdService()
	if service.Action == nil {
		t.Fatal("service command does not default to the table view")
	}
	requireCommandFlags(t, service, "filter", "local", "all", "verbose")
	show := commandByName(service.Commands, "show")
	if show == nil {
		t.Fatal("service show command is missing")
	}
	requireCommandFlags(t, show, "filter", "local", "all", "verbose")
	mine := commandByName(service.Commands, "mine")
	if mine == nil {
		t.Fatal("service mine command is missing")
	}
	requireCommandFlags(t, mine, "filter", "all", "verbose")
}

func TestPublishAndWithdrawSOCKS5Service(t *testing.T) {
	managed := zone.ZonePath("pek.catofes.")
	rt, managed := buildRouteTestRuntimeWithNetwork(t, true, func(network *zone.NetworkState) {
		putServiceIPAMRecord(t, network.Zones[zone.RootZone], "ipam/pools/fd42::_16", routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{
			Version: 1, Prefix: "fd42::/16", DelegatedTo: zone.RootZone, Active: true,
		})
		putServiceIPAMRecord(t, network.Zones[zone.RootZone], "ipam/assignments/fd42:1::_64", routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{
			Version: 1, Prefix: "fd42:1::/64", AssignedTo: managed, Active: true,
		})
	})
	if err := publishSOCKS5EndpointsWithConfig(rt.Config, []photonservice.SOCKS5Endpoint{{Region: "cn-east", Address: "fd42:1::20", Port: 3128}}, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("publish: %v", err)
	}
	common, _, err := loadOfflineOwnerViews(rt.Config)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after publish: %v", err)
	}
	record := common.State.Network.Zones[managed].Records["services/socks5"]
	parsed, err := photonservice.ParseSOCKS5Record(record)
	if err != nil || !parsed.IsActive() || record.Version != 1 {
		t.Fatalf("published record = %#v, parsed = %#v, error = %v", record, parsed, err)
	}
	if err := withdrawSOCKS5ServiceWithConfig(rt.Config, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	common, _, err = loadOfflineOwnerViews(rt.Config)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after withdraw: %v", err)
	}
	record = common.State.Network.Zones[managed].Records["services/socks5"]
	parsed, err = photonservice.ParseSOCKS5Record(record)
	if err != nil || parsed.IsActive() || record.Version != 2 {
		t.Fatalf("withdrawn record = %#v, parsed = %#v, error = %v", record, parsed, err)
	}
}

func TestPublishSOCKS5ServiceRejectsUnownedAddress(t *testing.T) {
	rt, _ := buildRouteTestRuntime(t)
	if err := publishSOCKS5EndpointsWithConfig(rt.Config, []photonservice.SOCKS5Endpoint{{Region: "cn", Address: "fd42:1::20", Port: 3128}}, rt.Now(), rt.Direct); err == nil {
		t.Fatal("expected unowned address error")
	}
}

func putServiceIPAMRecord(t *testing.T, state *zone.ZoneState, key, recordType string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	state.Records[key] = &zone.Record{Zone: state.Path, Key: key, Type: recordType, Value: data}
}
