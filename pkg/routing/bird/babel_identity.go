package bird

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// BabelProtocolName is shared by configuration generation and live identity
// observation so an unrelated Babel instance can never supply the binding.
func BabelProtocolName(netns string) string { return "photon_babel_" + sanitizeNetNSName(netns) }

// LocalBabelIdentity observes a complete on-wire ID from BIRD's own exported
// entry table. Only exact currently authorized local prefixes with metric zero
// are evidence: BIRD injects local routes at zero, while learned routes include
// a strictly positive link cost. A selected learned route to an assigned local
// prefix therefore cannot claim that remote router's ID as our own.
// No evidence returns an empty ID. Malformed or conflicting evidence is an
// error; callers must withdraw the binding in either case, never infer low bits.
func LocalBabelIdentity(output, protocol string, local []netip.Prefix) (string, error) {
	if len(output) > 1<<20 || protocol == "" {
		return "", fmt.Errorf("invalid Babel identity observation")
	}
	allowed := make(map[string]bool, len(local))
	for _, p := range local {
		if p.IsValid() && p == p.Masked() {
			allowed[p.String()] = true
		}
	}
	current := ""
	identity := ""
	for line := range strings.SplitSeq(stripCodes(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 && strings.HasSuffix(fields[0], ":") {
			current = strings.TrimSuffix(fields[0], ":")
			if current != protocol {
				return "", fmt.Errorf("unexpected Babel protocol %q", current)
			}
			continue
		}
		if !allowed[fields[0]] {
			continue
		}
		if current != protocol || len(fields) != 6 {
			return "", fmt.Errorf("malformed local Babel entry")
		}
		for i := 2; i < len(fields); i++ {
			bits := 32
			if i < 4 {
				bits = 16
			}
			if _, err := strconv.ParseUint(fields[i], 10, bits); err != nil {
				return "", fmt.Errorf("invalid local Babel entry counter")
			}
		}
		// Also require no learned route/source state for this witness prefix.
		// Ambiguous local/remote competition loses the binding rather than
		// allowing an imported entry to establish local identity.
		if fields[2] != "0" || fields[4] != "0" || fields[5] != "0" {
			continue
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) != 8 {
			return "", fmt.Errorf("incomplete Babel router ID")
		}
		for _, p := range parts {
			if len(p) != 2 {
				return "", fmt.Errorf("incomplete Babel router ID")
			}
		}
		text := strings.ToLower(strings.Join(parts, ""))
		raw, err := hex.DecodeString(text)
		if err != nil || len(raw) != 8 || text == "0000000000000000" || text == "ffffffffffffffff" {
			return "", fmt.Errorf("invalid Babel router ID")
		}
		if identity != "" && identity != text {
			return "", fmt.Errorf("conflicting local Babel router IDs")
		}
		identity = text
	}
	return identity, nil
}
