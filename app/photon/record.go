package main

import (
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type recordMutationResult struct {
	Zone    zone.ZonePath
	Key     string
	Version uint64
	DryRun  bool
}

func putRecord(path zone.ZonePath, key string, value []byte, recordType string, direct bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	if version, ok, err := putRecordViaControl(rt, path, key, value, recordType); ok {
		if err != nil {
			return err
		}
		fmt.Printf("put %s/%s version %d via daemon\n", path, key, version)
		return nil
	}
	if !direct {
		logControlFallback("record_put")
	}
	return putRecordDirect(rt, path, key, value, recordType)
}

func putRecordDirect(rt *AppContext, path zone.ZonePath, key string, value []byte, recordType string) error {
	result, err := applyOfflineCommonIntent(rt, corestate.PutRecordIntent{
		Zone: path, Key: key, Type: recordType, Value: append([]byte(nil), value...),
	}, false)
	if err != nil {
		return err
	}
	if result.Record == nil {
		return fmt.Errorf("record put did not return a record")
	}
	fmt.Printf("put %s/%s version %d\n", path, key, result.Record.Version)
	return nil
}

func getRecord(path zone.ZonePath, key string, verbose bool) error {
	record, err := loadRecord(path, key, 0)
	if err != nil {
		return err
	}
	return inspecttext.WriteRecord(os.Stdout, *record, verbose)
}

func debugRecord(path zone.ZonePath, key string, history int) error {
	record, err := loadRecord(path, key, history)
	if err != nil {
		return err
	}
	return inspecttext.WriteJSON(os.Stdout, record)
}

func loadRecord(path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, error) {
	rt, err := NewAppContext()
	if err != nil {
		return nil, err
	}
	if history < 0 {
		return nil, fmt.Errorf("history must be >= 0")
	}
	if record, ok, err := getRecordViaControl(rt, path, key, history); ok {
		if err != nil {
			return nil, err
		}
		return record, nil
	}
	logControlFallback("record_get")
	return getRecordDirect(rt, path, key, history)
}

func getRecordDirect(rt *AppContext, path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, error) {
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return nil, err
	}
	if common.State == nil {
		return nil, fmt.Errorf("common state is not initialized")
	}
	return lookupRecordDetailFromNetwork(common.State.Network, path, key, history)
}

func lookupRecordDetailFromNetwork(network *zone.NetworkState, path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, error) {
	if history < 0 {
		return nil, fmt.Errorf("history must be >= 0")
	}
	if network == nil {
		return nil, fmt.Errorf("state is nil")
	}
	zs := network.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	rec := zs.Records[key]
	if rec == nil {
		return nil, fmt.Errorf("record not found: %s/%s", path, key)
	}
	view := inspect.BuildRecordDetail(rec, zs.RecordHistory[key], history)
	return &view, nil
}
