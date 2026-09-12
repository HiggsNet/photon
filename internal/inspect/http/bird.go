package http

import "github.com/HiggsNet/photon/internal/inspect"

type BirdResponse struct {
	Instances          any                  `json:"instances"`
	LastRoutingFailure *inspect.FailureView `json:"last_routing_failure,omitempty"`
}
