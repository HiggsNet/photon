package text

import (
	"fmt"
	"io"
	"net"
	"strings"
	"text/tabwriter"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteServices(w io.Writer, view inspect.ServiceInspection, filter string, includeAll, localOnly, verbose bool) error {
	filter = strings.ToLower(strings.TrimSpace(filter))
	services := make([]inspect.ServiceView, 0, len(view.Services))
	eligibleCount := 0
	for _, service := range view.Services {
		if localOnly && !service.Local {
			continue
		}
		if !includeAll && service.Status == "withdrawn" {
			continue
		}
		eligibleCount++
		searchable := []string{
			service.ID,
			service.Type,
			string(service.Owner),
			service.Status,
			service.RecordKey,
			failureDisplay(service.Failure),
		}
		for _, endpoint := range service.Endpoints {
			searchable = append(searchable, endpoint.Region, endpoint.Address, fmt.Sprint(endpoint.Port))
		}
		if filter == "" || strings.Contains(strings.ToLower(strings.Join(searchable, " ")), filter) {
			services = append(services, service)
		}
	}

	endpointCount := 0
	for _, service := range services {
		endpointCount += max(1, len(service.Endpoints))
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Linef("managed_zone: %s", dash(string(view.ManagedZone)))
	out.Linef("services: %s", filteredCount(len(services), eligibleCount, filter))
	out.Linef("endpoints: %d", endpointCount)
	rows := make([][]string, 0, endpointCount+1)
	if verbose {
		rows = append(rows, []string{"SERVICE", "TYPE", "OWNER", "SCOPE", "REGION", "ENDPOINT", "STATUS", "VERSION", "UPDATED", "RECORD", "FAILURE"})
	} else {
		rows = append(rows, []string{"SERVICE", "TYPE", "OWNER", "SCOPE", "REGION", "ENDPOINT", "STATUS"})
	}
	for _, service := range services {
		endpoints := service.Endpoints
		if len(endpoints) == 0 {
			endpoints = []inspect.ServiceEndpointView{{}}
		}
		for _, endpoint := range endpoints {
			scope := "remote"
			if service.Local {
				scope = "local"
			}
			address := "-"
			if endpoint.Address != "" && endpoint.Port != 0 {
				address = net.JoinHostPort(endpoint.Address, fmt.Sprint(endpoint.Port))
			}
			if verbose {
				rows = append(rows, []string{
					service.ID,
					dash(service.Type),
					string(service.Owner),
					scope,
					dash(endpoint.Region),
					address,
					dash(service.Status),
					fmt.Sprint(service.Version),
					formatUnixTime(service.UpdatedUnix),
					dash(service.RecordKey),
					escapeTableCell(failureDisplay(service.Failure)),
				})
			} else {
				rows = append(rows, []string{
					service.ID,
					dash(service.Type),
					string(service.Owner),
					scope,
					dash(endpoint.Region),
					address,
					dash(service.Status),
				})
			}
		}
	}
	writeAlignedRows(out, rows, 2)
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}
