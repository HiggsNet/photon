package ipsec

func mustRuntimeSpecForPortGeneration(spec TransportLinkSpec, generation uint64) TransportLinkSpec {
	out, err := RuntimeSpecForPortGeneration(spec, LinkGroupSpec{}, generation)
	if err != nil {
		panic(err)
	}
	return out
}
