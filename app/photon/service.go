package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

const socks5RecordName = "socks5"

func showServices(filter string, includeAll, localOnly, verbose bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.ServiceInspection](config, controlRequest{Method: "services_view"}, false); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteServices(os.Stdout, view, filter, includeAll, localOnly, verbose)
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil {
		return errors.New("common state is not initialized")
	}
	view := inspect.BuildServiceInspection(common.State, time.Now())
	return inspecttext.WriteServices(os.Stdout, view, filter, includeAll, localOnly, verbose)
}

type serviceMutationRequest struct {
	Operation    string                         `json:"operation"`
	Endpoints    []photonservice.SOCKS5Endpoint `json:"endpoints,omitempty"`
	Type         string                         `json:"type,omitempty"`
	ServerName   string                         `json:"server_name,omitempty"`
	Fingerprint  string                         `json:"fingerprint,omitempty"`
	AuthRequired bool                           `json:"auth_required,omitempty"`
	DryRun       bool                           `json:"dry_run,omitempty"`
}

const (
	serviceOperationPublish  = "publish"
	serviceOperationWithdraw = "withdraw"
)

func commonServiceIntent(request serviceMutationRequest) (corestate.LocalIntent, error) {
	if request.Type == photonservice.TypeHTTP {
		switch request.Operation {
		case serviceOperationPublish:
			return corestate.PublishHTTPIntent{Service: photonservice.HTTPRecord{Type: request.Type, Endpoints: append([]photonservice.SOCKS5Endpoint(nil), request.Endpoints...), AuthRequired: request.AuthRequired}}, nil
		case serviceOperationWithdraw:
			return corestate.WithdrawHTTPIntent{}, nil
		}
	}
	if request.Type == photonservice.TypeTrustTunnel {
		switch request.Operation {
		case serviceOperationPublish:
			return corestate.PublishTrustTunnelIntent{Service: photonservice.TrustTunnelRecord{Type: request.Type, Endpoints: append([]photonservice.SOCKS5Endpoint(nil), request.Endpoints...), ServerName: request.ServerName, Fingerprint: request.Fingerprint}}, nil
		case serviceOperationWithdraw:
			return corestate.WithdrawTrustTunnelIntent{}, nil
		}
	}
	if request.Type != "" && request.Type != photonservice.TypeSOCKS5 {
		return nil, fmt.Errorf("unsupported service type %q", request.Type)
	}
	switch request.Operation {
	case serviceOperationPublish:
		return corestate.PublishSOCKS5Intent{Endpoints: append([]photonservice.SOCKS5Endpoint(nil), request.Endpoints...)}, nil
	case serviceOperationWithdraw:
		return corestate.WithdrawSOCKS5Intent{}, nil
	default:
		return nil, fmt.Errorf("unsupported service operation %q", request.Operation)
	}
}

func publishSOCKS5Endpoints(endpoints []photonservice.SOCKS5Endpoint, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return submitServiceMutation(config, serviceMutationRequest{
		Operation: serviceOperationPublish,
		Endpoints: endpoints,
	}, time.Now(), direct)
}

func parseSOCKS5EndpointFlags(values []string, legacyRegion, legacyAddress string, legacyPort uint16) ([]photonservice.SOCKS5Endpoint, error) {
	if len(values) == 0 {
		if legacyRegion == "" || legacyAddress == "" {
			return nil, fmt.Errorf("at least one --endpoint is required")
		}
		return []photonservice.SOCKS5Endpoint{{Region: legacyRegion, Address: legacyAddress, Port: legacyPort}}, nil
	}
	if legacyRegion != "" || legacyAddress != "" {
		return nil, fmt.Errorf("--endpoint cannot be combined with --region or --address")
	}
	endpoints := make([]photonservice.SOCKS5Endpoint, 0, len(values))
	for _, value := range values {
		parts := strings.Split(value, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid endpoint %q: expected region,address,port", value)
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid endpoint port in %q", value)
		}
		endpoints = append(endpoints, photonservice.SOCKS5Endpoint{Region: parts[0], Address: parts[1], Port: uint16(port)})
	}
	return endpoints, nil
}

func withdrawSOCKS5Service(direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return submitServiceMutation(config, serviceMutationRequest{Operation: serviceOperationWithdraw}, time.Now(), direct)
}

func submitServiceMutation(config *appConfig, request serviceMutationRequest, now time.Time, direct bool) error {
	name := socks5RecordName
	if request.Type != "" {
		name = request.Type
	}
	var operation string
	switch request.Operation {
	case serviceOperationPublish:
		operation = "published"
	case serviceOperationWithdraw:
		operation = "withdrew"
	default:
		return fmt.Errorf("unsupported service operation %q", request.Operation)
	}
	method := serviceMutationMethod(request.Type)
	if version, ok, err := sendVersionedMutationViaControl(config, controlRequest{Method: method, Service: &request}, direct); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s service %s version %d via daemon\n", operation, name, version)
		return nil
	}
	intent, err := commonServiceIntent(request)
	if err != nil {
		return err
	}
	result, err := applyOfflineCommonIntent(config, intent, request.DryRun, now)
	if err != nil {
		return err
	}
	if result.Record == nil {
		return errors.New("service mutation did not return a record")
	}
	fmt.Printf("%s service %s version %d\n", operation, name, result.Record.Version)
	return nil
}

func serviceMutationMethod(kind string) string {
	switch kind {
	case photonservice.TypeHTTP:
		return "http_service_mutate"
	case photonservice.TypeTrustTunnel:
		return "trusttunnel_service_mutate"
	default:
		return "service_mutate"
	}
}
