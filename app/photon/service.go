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
	Operation string                         `json:"operation"`
	Endpoints []photonservice.SOCKS5Endpoint `json:"endpoints,omitempty"`
	DryRun    bool                           `json:"dry_run,omitempty"`
}

const (
	serviceOperationPublish  = "publish"
	serviceOperationWithdraw = "withdraw"
)

func publishSOCKS5Endpoints(endpoints []photonservice.SOCKS5Endpoint, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return publishSOCKS5EndpointsWithConfig(config, endpoints, time.Now(), direct)
}

func publishSOCKS5EndpointsWithConfig(config *appConfig, endpoints []photonservice.SOCKS5Endpoint, now time.Time, direct bool) error {
	return submitServiceMutation(config, serviceMutationRequest{
		Operation: serviceOperationPublish,
		Endpoints: append([]photonservice.SOCKS5Endpoint(nil), endpoints...),
	}, "published", now, direct)
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

	return withdrawSOCKS5ServiceWithConfig(config, time.Now(), direct)
}

func withdrawSOCKS5ServiceWithConfig(config *appConfig, now time.Time, direct bool) error {
	return submitServiceMutation(config, serviceMutationRequest{Operation: serviceOperationWithdraw}, "withdrew", now, direct)
}

func submitServiceMutation(config *appConfig, request serviceMutationRequest, operation string, now time.Time, direct bool) error {
	if version, ok, err := sendVersionedMutationViaControl(config, controlRequest{Method: "service_mutate", Service: &request}, direct); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s service %s version %d via daemon\n", operation, socks5RecordName, version)
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
	fmt.Printf("%s service %s version %d\n", operation, socks5RecordName, result.Record.Version)
	return nil
}
