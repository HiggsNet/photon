package inspect

import (
	"sort"
	"strings"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

type ServiceInspection struct {
	ManagedZone zone.ZonePath
	Services    []ServiceView
}

type ServiceView struct {
	ID          string
	Type        string
	Owner       zone.ZonePath
	Local       bool
	Active      bool
	Status      string
	Endpoints   []ServiceEndpointView
	Version     uint64
	UpdatedUnix int64
	RecordKey   string
	Failure     *FailureView
}

type ServiceEndpointView struct {
	Region  string
	Address string
	Port    uint16
}

func BuildServiceInspection(state *corestate.VerifiedState, now time.Time) ServiceInspection {
	if state == nil {
		return ServiceInspection{}
	}
	view := ServiceInspection{ManagedZone: state.ManagedZone}
	if state.Network == nil {
		return view
	}

	paths := make([]zone.ZonePath, 0, len(state.Network.Zones))
	for path := range state.Network.Zones {
		paths = append(paths, path)
	}
	SortZonePaths(paths)
	for _, path := range paths {
		if state.Network.IsZoneRevoked(path, now) {
			continue
		}
		zoneState := state.Network.Zones[path]
		if zoneState == nil {
			continue
		}
		keys := make([]string, 0, len(zoneState.Records))
		for key := range zoneState.Records {
			if strings.HasPrefix(key, photonservice.RecordKeyPrefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			record := zoneState.Records[key]
			if record == nil || record.Type != photonservice.RecordTypeSOCKS5 {
				continue
			}
			serviceView := ServiceView{
				ID:          strings.TrimPrefix(key, photonservice.RecordKeyPrefix),
				Type:        photonservice.TypeSOCKS5,
				Owner:       path,
				Local:       path == state.ManagedZone,
				Version:     record.Version,
				UpdatedUnix: record.Timestamp,
				RecordKey:   record.Key,
			}
			value, err := photonservice.ParseSOCKS5Record(record)
			if err != nil {
				serviceView.Status = "invalid"
				serviceView.Failure = BuildFailure(FailureCodeServiceRecord, err)
				view.Services = append(view.Services, serviceView)
				continue
			}
			serviceView.Active = value.IsActive()
			serviceView.Status = "withdrawn"
			if serviceView.Active {
				serviceView.Status = "active"
			}
			for _, endpoint := range value.EffectiveEndpoints() {
				serviceView.Endpoints = append(serviceView.Endpoints, ServiceEndpointView{
					Region:  endpoint.Region,
					Address: endpoint.Address,
					Port:    endpoint.Port,
				})
			}
			view.Services = append(view.Services, serviceView)
		}
	}
	return view
}
