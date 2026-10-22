package photonlinux

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type IPsecInterfaceAddress struct {
	Address                          netip.Addr
	Temporary, Deprecated, Tentative bool
}

type IPsecInterface struct {
	Name      string
	Up        bool
	Addresses []IPsecInterfaceAddress
}

// SelectIPsecInterfaceAddresses accepts a detached host observation, never changes
// an interface, and converges each explicitly selected device independently.
func SelectIPsecInterfaceAddresses(rules []IPsecAnnounceInterface, inventory []IPsecInterface) ([]ipsec.AddressAdvertisement, error) {
	var out []ipsec.AddressAdvertisement
	var problems []error
	for _, rule := range rules {
		var found *IPsecInterface
		for i := range inventory {
			if inventory[i].Name == rule.Name {
				found = &inventory[i]
				break
			}
		}
		if found == nil || !found.Up {
			problems = append(problems, fmt.Errorf("announce interface %q is missing or down", rule.Name))
			continue
		}
		for _, candidate := range found.Addresses {
			addr := candidate.Address
			if candidate.Temporary || candidate.Deprecated || candidate.Tentative || !addr.IsValid() || addr.Is4In6() || addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() || !rule.Allows(addr) {
				continue
			}
			out = append(out, ipsec.AddressAdvertisement{ID: "interface-" + rule.Name + "-" + addr.String(), Source: ipsec.SourceDiscovery, Address: addr.String(), Family: ipsecFamily(addr.String()), Priority: rule.Priority, Reachability: ipsecReachability(addr.String())})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out, errors.Join(problems...)
}
