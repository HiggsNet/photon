package state

import "maps"

func ClonePeerLifecycleCleanups(in map[string]PeerLifecycleCleanupState) map[string]PeerLifecycleCleanupState {
	return maps.Clone(in)
}

func CloneRoutingReconcileState(in *RoutingReconcileState) *RoutingReconcileState {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func CloneIPsecTransportKeyState(in *IPsecTransportKeyState) *IPsecTransportKeyState {
	if in == nil {
		return nil
	}
	out := *in
	out.PublicKey = cloneSlice(in.PublicKey)
	out.PrivateKey = cloneSlice(in.PrivateKey)
	return &out
}

func CloneEndpointACLs(in map[string]EndpointACL) map[string]EndpointACL {
	if in == nil {
		return nil
	}
	out := make(map[string]EndpointACL, len(in))
	for name, acl := range in {
		acl.Selectors = cloneSlice(acl.Selectors)
		out[name] = acl
	}
	return out
}

func CloneBirdInstances(in map[string]*BirdInstanceState) map[string]*BirdInstanceState {
	if in == nil {
		return nil
	}
	out := make(map[string]*BirdInstanceState, len(in))
	for id, instance := range in {
		out[id] = CloneBirdInstance(instance)
	}
	return out
}

func CloneBirdInstance(in *BirdInstanceState) *BirdInstanceState {
	if in == nil {
		return nil
	}
	out := *in
	out.Overlays = cloneSlice(in.Overlays)
	return &out
}

func CloneFirewallReconcileState(in *FirewallReconcileState) *FirewallReconcileState {
	if in == nil {
		return nil
	}
	out := *in
	if in.Instances != nil {
		out.Instances = make(map[string]*FirewallReconcileInstance, len(in.Instances))
		for id, entry := range in.Instances {
			if entry == nil {
				out.Instances[id] = nil
				continue
			}
			copyEntry := *entry
			out.Instances[id] = &copyEntry
		}
	}
	return &out
}

func cloneSlice[T any](in []T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	copy(out, in)
	return out
}
