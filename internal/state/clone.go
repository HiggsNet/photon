package state

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

func cloneSlice[T any](in []T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	copy(out, in)
	return out
}
