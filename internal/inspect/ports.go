package inspect

import (
	"fmt"
	"net"
)

// Selection/local-port data is not part of the committed runtime view.
func DebugPortGenerationSummary(rotation LinkRotation) string {
	return fmt.Sprintf("-/%d/%d", rotation.RemoteGeneration, rotation.StagedGeneration)
}

func DebugPortSummary(selectedEndpoint, runtimeEndpoint, stagedEndpoint string) string {
	return fmt.Sprintf("-/%s/%s/%s", debugDash(DebugEndpointPort(selectedEndpoint)), debugDash(DebugEndpointPort(runtimeEndpoint)), debugDash(DebugEndpointPort(stagedEndpoint)))
}

func DebugEndpointPort(endpoint string) string {
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	return port
}

func debugDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
