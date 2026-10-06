package bird

import (
	"bytes"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTableID        = "main"
	defaultMetricBase     = 100
	defaultMetricStaged   = 1200
	defaultMetricDraining = 2400
	defaultDeviceScanTime = 5 * time.Second
	defaultLogTarget      = "log syslog all"

	// Default Babel mesh tuning makes roughly 48 ms of total RTT improvement
	// worth one additional lossless hop. The slow RTT EMA limits reactions to
	// millisecond-scale jitter.
	DefaultBabelRTTCost        = 1024
	DefaultBabelRTTMin         = 10 * time.Millisecond
	DefaultBabelRTTMax         = 500 * time.Millisecond
	DefaultBabelRTTDecay       = 12
	DefaultBabelHelloInterval  = 4 * time.Second
	DefaultBabelUpdateInterval = 16 * time.Second
)

// DefaultConfigGenerator generates BIRD configuration files from
// BirdInstanceSpec and authorized prefix sets.
type DefaultConfigGenerator struct{}

// Generate renders a complete bird.conf for the supplied spec.
func (DefaultConfigGenerator) Generate(spec BirdInstanceSpec, importSet, exportSet []netip.Prefix) ([]byte, error) {
	spec = applyDefaults(spec)
	if err := validateSpec(spec); err != nil {
		return nil, err
	}

	cfg := buildConfig(spec, importSet, exportSet)
	return renderConfig(cfg)
}

func applyDefaults(spec BirdInstanceSpec) BirdInstanceSpec {
	if spec.TableID == "" {
		spec.TableID = defaultTableID
	}
	if spec.MetricBase == 0 {
		spec.MetricBase = defaultMetricBase
	}
	if spec.MetricStaged == 0 {
		spec.MetricStaged = defaultMetricStaged
	}
	if spec.MetricDraining == 0 {
		spec.MetricDraining = defaultMetricDraining
	}
	if spec.DeviceScanTime == 0 {
		spec.DeviceScanTime = defaultDeviceScanTime
	}
	if spec.BabelRTTCost == 0 {
		spec.BabelRTTCost = DefaultBabelRTTCost
	}
	if spec.BabelRTTMin == 0 {
		spec.BabelRTTMin = DefaultBabelRTTMin
	}
	if spec.BabelRTTMax == 0 {
		spec.BabelRTTMax = DefaultBabelRTTMax
	}
	if spec.BabelRTTDecay == 0 {
		spec.BabelRTTDecay = DefaultBabelRTTDecay
	}
	if spec.BabelHelloInterval == 0 {
		spec.BabelHelloInterval = DefaultBabelHelloInterval
	}
	if spec.BabelUpdateInterval == 0 {
		spec.BabelUpdateInterval = DefaultBabelUpdateInterval
	}
	if spec.LogTarget == "" {
		spec.LogTarget = defaultLogTarget
	}
	if spec.InternalTableName == "" {
		spec.InternalTableName = defaultInternalTableName(spec.NetNSName)
	}
	// Merge legacy InterfacePattern into InterfacePatterns.
	if spec.InterfacePattern != "" {
		spec.InterfacePatterns = mergeInterfacePatterns(spec.InterfacePatterns, spec.InterfacePattern)
		spec.InterfacePattern = ""
	}
	if len(spec.InterfacePatterns) == 0 {
		spec.InterfacePatterns = []string{"phx*"}
	}
	return spec
}

func mergeInterfacePatterns(patterns []string, extra string) []string {
	seen := make(map[string]bool, len(patterns)+1)
	var out []string
	for _, p := range patterns {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if !seen[extra] {
		out = append(out, extra)
	}
	return out
}

func validateSpec(spec BirdInstanceSpec) error {
	if spec.RouterID == 0 {
		return fmt.Errorf("bird: router id is required")
	}
	if spec.NetNSName == "" {
		return fmt.Errorf("bird: netns name is required")
	}
	switch spec.Mode {
	case BirdModeManaged, BirdModeExternal:
		// ok
	case BirdModeDisabled:
		return fmt.Errorf("bird: cannot generate config for disabled mode")
	default:
		return fmt.Errorf("bird: invalid mode %q", spec.Mode)
	}
	if spec.TableID != defaultTableID {
		if _, err := strconv.ParseUint(spec.TableID, 10, 32); err != nil {
			return fmt.Errorf("bird: table id must be %q or a numeric kernel table id", defaultTableID)
		}
	}
	if spec.Upstream != nil && strings.TrimSpace(spec.Upstream.Interface) == "" {
		return fmt.Errorf("bird: upstream interface is required")
	}
	seenInterfaces := make(map[string]struct{}, len(spec.InterfacePolicies))
	for _, policy := range spec.InterfacePolicies {
		if strings.TrimSpace(policy.InterfaceName) == "" {
			return fmt.Errorf("bird: interface policy name is required")
		}
		if policy.Metric == 0 {
			return fmt.Errorf("bird: interface policy metric for %q must be positive", policy.InterfaceName)
		}
		if _, exists := seenInterfaces[policy.InterfaceName]; exists {
			return fmt.Errorf("bird: duplicate interface policy for %q", policy.InterfaceName)
		}
		seenInterfaces[policy.InterfaceName] = struct{}{}
	}
	if spec.BabelRTTCost >= 65535 {
		return fmt.Errorf("bird: Babel RTT cost must be less than 65535")
	}
	if spec.BabelRTTDecay < 1 || spec.BabelRTTDecay > 256 {
		return fmt.Errorf("bird: Babel RTT decay must be between 1 and 256")
	}
	if err := validateBabelDuration("RTT min", spec.BabelRTTMin); err != nil {
		return err
	}
	if err := validateBabelDuration("RTT max", spec.BabelRTTMax); err != nil {
		return err
	}
	if spec.BabelRTTMax <= spec.BabelRTTMin {
		return fmt.Errorf("bird: Babel RTT max must be greater than RTT min")
	}
	if err := validateBabelDuration("Hello interval", spec.BabelHelloInterval); err != nil {
		return err
	}
	if err := validateBabelDuration("Update interval", spec.BabelUpdateInterval); err != nil {
		return err
	}
	for _, route := range spec.StaticRoutes {
		if route.NextHop.IsValid() && route.Via != "" && !isBirdQuotedSymbol(route.Via) {
			return fmt.Errorf("bird: static route interface %q cannot be represented as a BIRD scoped next-hop", route.Via)
		}
	}
	if !filepath.IsAbs(spec.ControlSocketPath) {
		return fmt.Errorf("bird: control socket path must be absolute")
	}
	if !filepath.IsAbs(spec.PIDFilePath) {
		return fmt.Errorf("bird: pid file path must be absolute")
	}
	if !filepath.IsAbs(spec.ConfigPath) {
		return fmt.Errorf("bird: config path must be absolute")
	}
	return nil
}

func validateBabelDuration(name string, value time.Duration) error {
	if value < time.Millisecond || value%time.Millisecond != 0 {
		return fmt.Errorf("bird: Babel %s must be a positive whole number of milliseconds", name)
	}
	return nil
}

func buildConfig(spec BirdInstanceSpec, importSet, exportSet []netip.Prefix) BirdConfig {
	suffix := sanitizeNetNSName(spec.NetNSName)
	internalTable := spec.InternalTableName
	ipv4Table := internalTable + "4"
	ipv6Table := internalTable + "6"
	kernelName := "photon_kern_" + suffix
	kernelName4 := kernelName + "4"
	kernelName6 := kernelName + "6"
	babelName := BabelProtocolName(spec.NetNSName)
	importFilterName := "photon_import_" + suffix
	exportFilterName := "photon_export_" + suffix
	staticName := "photon_static_" + suffix

	var kernelTableID uint32
	if spec.TableID != defaultTableID {
		if n, err := strconv.ParseUint(spec.TableID, 10, 32); err == nil {
			kernelTableID = uint32(n)
		}
	}

	importFilter := FilterBlock{
		Name: importFilterName,
		Body: RenderFilter(importFilterName, importSet, spec.BogonPrefixes),
	}
	exportFilter := FilterBlock{
		Name: exportFilterName,
		Body: RenderFilter(exportFilterName, exportSet, spec.BogonPrefixes),
	}

	interfacePatterns := spec.InterfacePatterns
	if len(interfacePatterns) == 0 {
		interfacePatterns = []string{"phx*"}
	}

	// Determine if upstream is enabled and build upstream interface block.
	var upstreamBlock *BabelInterfaceBlock
	if spec.Upstream != nil {
		upstreamBlock = &BabelInterfaceBlock{
			InterfacePattern: spec.Upstream.Interface,
			InterfaceType:    BabelInterfaceTypeDefault,
			RTTMetrics:       false,
			MetricBase:       spec.MetricBase,
			HelloInterval:    spec.BabelHelloInterval,
			UpdateInterval:   spec.BabelUpdateInterval,
		}
	}
	interfaceBlocks := make([]BabelInterfaceBlock, 0, len(spec.InterfacePolicies))
	for _, policy := range spec.InterfacePolicies {
		interfaceBlocks = append(interfaceBlocks, BabelInterfaceBlock{
			InterfacePattern: policy.InterfaceName,
			InterfaceType:    BabelInterfaceTypeWireless,
			RTTMetrics:       true,
			MetricBase:       policy.Metric,
			RTTCost:          spec.BabelRTTCost,
			RTTMin:           spec.BabelRTTMin,
			RTTMax:           spec.BabelRTTMax,
			RTTDecay:         spec.BabelRTTDecay,
			HelloInterval:    spec.BabelHelloInterval,
			UpdateInterval:   spec.BabelUpdateInterval,
		})
	}
	sort.Slice(interfaceBlocks, func(i, j int) bool {
		return interfaceBlocks[i].InterfacePattern < interfaceBlocks[j].InterfacePattern
	})

	// Build static route block if any static routes are specified.
	var staticBlocks []StaticRouteBlock
	if len(spec.StaticRoutes) > 0 {
		block := StaticRouteBlock{Name: staticName}
		for _, sr := range spec.StaticRoutes {
			route := StaticRoute(sr)
			if sr.Prefix.Addr().Is4() {
				block.IPv4Routes = append(block.IPv4Routes, route)
			} else {
				block.IPv6Routes = append(block.IPv6Routes, route)
			}
		}
		staticBlocks = append(staticBlocks, block)
	}

	return BirdConfig{
		RouterID:       spec.RouterID,
		LogTarget:      spec.LogTarget,
		ListenSocket:   spec.ControlSocketPath,
		DeviceScanTime: spec.DeviceScanTime,
		IPv4Table:      ipv4Table,
		IPv6Table:      ipv6Table,
		KernelTableID:  kernelTableID,
		Kernel: []KernelProtocolBlock{
			{
				Name:            kernelName4,
				IPv4Table:       ipv4Table,
				KernelTableID:   kernelTableID,
				Learn:           false,
				Persist:         false,
				MergePaths:      spec.ECMP,
				MergePathsLimit: spec.ECMPLimit,
			},
			{
				Name:            kernelName6,
				IPv6Table:       ipv6Table,
				KernelTableID:   kernelTableID,
				Learn:           false,
				Persist:         false,
				MergePaths:      spec.ECMP,
				MergePathsLimit: spec.ECMPLimit,
			},
		},
		Babel: BabelProtocolBlock{
			Name:             babelName,
			IPv4Table:        ipv4Table,
			IPv6Table:        ipv6Table,
			InterfacePattern: renderInterfacePatterns(interfacePatterns),
			InterfaceType:    BabelInterfaceTypeWireless,
			RTTMetrics:       true,
			MetricBase:       spec.MetricBase,
			MetricStaged:     spec.MetricStaged,
			MetricDraining:   spec.MetricDraining,
			RTTCost:          spec.BabelRTTCost,
			RTTMin:           spec.BabelRTTMin,
			RTTMax:           spec.BabelRTTMax,
			RTTDecay:         spec.BabelRTTDecay,
			HelloInterval:    spec.BabelHelloInterval,
			UpdateInterval:   spec.BabelUpdateInterval,
			InterfaceBlocks:  interfaceBlocks,
			Auth:             spec.BabelAuth,
			UpstreamBlock:    upstreamBlock,
		},
		ImportFilters: []FilterBlock{importFilter},
		ExportFilters: []FilterBlock{exportFilter},
		StaticRoutes:  staticBlocks,
	}
}

// renderInterfacePatterns renders multiple BIRD interface patterns as a
// comma-separated list of quoted strings, e.g. "phx*", "wg*".
func renderInterfacePatterns(patterns []string) string {
	quoted := make([]string, len(patterns))
	for i, p := range patterns {
		quoted[i] = fmt.Sprintf("%q", p)
	}
	return strings.Join(quoted, ", ")
}

func renderConfig(cfg BirdConfig) ([]byte, error) {
	var b bytes.Buffer

	fmt.Fprintln(&b, "# Photon-generated BIRD config")
	fmt.Fprintln(&b, "# Do not edit manually.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "%s;\n", cfg.LogTarget)
	fmt.Fprintf(&b, "router id %s;\n", formatRouterID(cfg.RouterID))
	fmt.Fprintln(&b, "# Control socket path is set on the bird command line with -s.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "protocol device {\n    scan time %d;\n}\n\n", int(cfg.DeviceScanTime.Seconds()))

	if cfg.IPv4Table != "" {
		fmt.Fprintf(&b, "ipv4 table %s;\n", cfg.IPv4Table)
	}
	if cfg.IPv6Table != "" {
		fmt.Fprintf(&b, "ipv6 table %s;\n", cfg.IPv6Table)
	}
	if cfg.IPv4Table != "" || cfg.IPv6Table != "" {
		fmt.Fprintln(&b)
	}

	for _, kp := range cfg.Kernel {
		fmt.Fprintf(&b, "protocol kernel %s {\n", kp.Name)
		if kp.IPv4Table != "" {
			fmt.Fprintf(&b, "    ipv4 { table %s; export all; };\n", kp.IPv4Table)
		}
		if kp.IPv6Table != "" {
			fmt.Fprintf(&b, "    ipv6 { table %s; export all; };\n", kp.IPv6Table)
		}
		if kp.KernelTableID != 0 {
			fmt.Fprintf(&b, "    kernel table %d;\n", kp.KernelTableID)
		}
		if kp.MergePaths {
			if kp.MergePathsLimit > 0 {
				fmt.Fprintf(&b, "    merge paths on limit %d;\n", kp.MergePathsLimit)
			} else {
				fmt.Fprintln(&b, "    merge paths on;")
			}
		}
		fmt.Fprintln(&b, "}")
		fmt.Fprintln(&b)
	}

	for _, f := range cfg.ImportFilters {
		fmt.Fprintln(&b, f.Body)
		fmt.Fprintln(&b)
	}
	for _, f := range cfg.ExportFilters {
		fmt.Fprintln(&b, f.Body)
		fmt.Fprintln(&b)
	}

	fmt.Fprintf(&b, "protocol babel %s {\n", cfg.Babel.Name)
	// BIRD resets the Babel sequence number when the protocol instance starts.
	// Randomizing the high half of Babel's 64-bit router ID prevents peers from
	// rejecting post-restart announcements as stale while preserving Photon's
	// stable 32-bit BIRD router ID in the low half.
	fmt.Fprintln(&b, "    randomize router id;")
	if cfg.Babel.IPv4Table != "" {
		fmt.Fprintln(&b, "    ipv4 {")
		fmt.Fprintf(&b, "        table %s;\n", cfg.Babel.IPv4Table)
		if len(cfg.ImportFilters) > 0 {
			fmt.Fprintf(&b, "        import filter %s;\n", cfg.ImportFilters[0].Name)
		}
		if len(cfg.ExportFilters) > 0 {
			fmt.Fprintf(&b, "        export filter %s;\n", cfg.ExportFilters[0].Name)
		}
		fmt.Fprintln(&b, "    };")
	}
	if cfg.Babel.IPv6Table != "" {
		fmt.Fprintln(&b, "    ipv6 {")
		fmt.Fprintf(&b, "        table %s;\n", cfg.Babel.IPv6Table)
		if len(cfg.ImportFilters) > 0 {
			fmt.Fprintf(&b, "        import filter %s;\n", cfg.ImportFilters[0].Name)
		}
		if len(cfg.ExportFilters) > 0 {
			fmt.Fprintf(&b, "        export filter %s;\n", cfg.ExportFilters[0].Name)
		}
		fmt.Fprintln(&b, "    };")
	}
	for _, block := range cfg.Babel.InterfaceBlocks {
		renderBabelInterfaceBlock(&b, block, cfg.Babel.Auth)
	}
	if cfg.Babel.InterfacePattern != "" {
		fmt.Fprintf(&b, "    interface %s {\n", cfg.Babel.InterfacePattern)
		if cfg.Babel.InterfaceType != BabelInterfaceTypeDefault {
			fmt.Fprintf(&b, "        type %s;\n", cfg.Babel.InterfaceType)
		}
		fmt.Fprintf(&b, "        rxcost %d;\n", cfg.Babel.MetricBase)
		if cfg.Babel.RTTMetrics {
			renderBabelRTTTuning(&b, cfg.Babel.RTTCost, cfg.Babel.RTTMin, cfg.Babel.RTTMax, cfg.Babel.RTTDecay)
		}
		renderBabelIntervals(&b, cfg.Babel.HelloInterval, cfg.Babel.UpdateInterval)
		if cfg.Babel.Auth != nil && cfg.Babel.Auth.Enabled {
			fmt.Fprintf(&b, "        auth %q key id %d password %q;\n", cfg.Babel.Auth.Algorithm, cfg.Babel.Auth.KeyID, cfg.Babel.Auth.Password)
		}
		fmt.Fprintln(&b, "    };")
	}
	// Upstream veth interface block (default wired behavior, no RTT metrics).
	if cfg.Babel.UpstreamBlock != nil {
		ub := cfg.Babel.UpstreamBlock
		fmt.Fprintf(&b, "    interface %q {\n", ub.InterfacePattern)
		// Do not emit a type for veth; BIRD's default wired behavior is used.
		fmt.Fprintf(&b, "        rxcost %d;\n", ub.MetricBase)
		renderBabelIntervals(&b, ub.HelloInterval, ub.UpdateInterval)
		fmt.Fprintln(&b, "    };")
	}
	fmt.Fprintln(&b, "}")

	// Static route blocks.
	for _, sr := range cfg.StaticRoutes {
		renderStaticRouteBlock(&b, sr, cfg.IPv4Table, cfg.IPv6Table)
	}

	return b.Bytes(), nil
}

func renderBabelInterfaceBlock(b *bytes.Buffer, block BabelInterfaceBlock, auth *BabelAuthSpec) {
	fmt.Fprintf(b, "    interface %q {\n", block.InterfacePattern)
	if block.InterfaceType != BabelInterfaceTypeDefault {
		fmt.Fprintf(b, "        type %s;\n", block.InterfaceType)
	}
	fmt.Fprintf(b, "        rxcost %d;\n", block.MetricBase)
	if block.RTTMetrics {
		renderBabelRTTTuning(b, block.RTTCost, block.RTTMin, block.RTTMax, block.RTTDecay)
	}
	renderBabelIntervals(b, block.HelloInterval, block.UpdateInterval)
	if auth != nil && auth.Enabled {
		fmt.Fprintf(b, "        auth %q key id %d password %q;\n", auth.Algorithm, auth.KeyID, auth.Password)
	}
	fmt.Fprintln(b, "    };")
}

func renderBabelRTTTuning(b *bytes.Buffer, cost uint, min, max time.Duration, decay uint) {
	fmt.Fprintf(b, "        rtt cost %d;\n", cost)
	fmt.Fprintf(b, "        rtt min %s;\n", formatBabelDuration(min))
	fmt.Fprintf(b, "        rtt max %s;\n", formatBabelDuration(max))
	fmt.Fprintf(b, "        rtt decay %d;\n", decay)
}

func renderBabelIntervals(b *bytes.Buffer, hello, update time.Duration) {
	fmt.Fprintf(b, "        hello interval %s;\n", formatBabelDuration(hello))
	fmt.Fprintf(b, "        update interval %s;\n", formatBabelDuration(update))
}

func formatBabelDuration(value time.Duration) string {
	if value%time.Second == 0 {
		return fmt.Sprintf("%d s", value/time.Second)
	}
	return fmt.Sprintf("%d ms", value/time.Millisecond)
}

// renderStaticRouteBlock renders one "protocol static { ... }" block.
func renderStaticRouteBlock(b *bytes.Buffer, sr StaticRouteBlock, ipv4Table, ipv6Table string) {
	fmt.Fprintf(b, "\nprotocol static %s {\n", sr.Name)
	if ipv4Table != "" && len(sr.IPv4Routes) > 0 {
		fmt.Fprintf(b, "    ipv4 { table %s; };\n", ipv4Table)
		for _, r := range sr.IPv4Routes {
			renderStaticRouteLine(b, r)
		}
	}
	if ipv6Table != "" && len(sr.IPv6Routes) > 0 {
		fmt.Fprintf(b, "    ipv6 { table %s; };\n", ipv6Table)
		for _, r := range sr.IPv6Routes {
			renderStaticRouteLine(b, r)
		}
	}
	fmt.Fprintln(b, "}")
}

func renderStaticRouteLine(b *bytes.Buffer, r StaticRoute) {
	if r.Blackhole {
		fmt.Fprintf(b, "    route %s blackhole;\n", r.Prefix.String())
		return
	}
	if r.NextHop.IsValid() && r.Via != "" {
		// BIRD 2.14 (shipped by Ubuntu 24.04) does not accept the newer
		// "via GATEWAY dev INTERFACE" form. A scoped next-hop is accepted by
		// both BIRD 2.14 and newer BIRD 2.x releases.
		fmt.Fprintf(b, "    route %s via %s%%'%s';\n", r.Prefix.String(), r.NextHop.String(), r.Via)
		return
	}
	if r.NextHop.IsValid() {
		fmt.Fprintf(b, "    route %s via %s;\n", r.Prefix.String(), r.NextHop.String())
		return
	}
	if r.Via != "" {
		fmt.Fprintf(b, "    route %s via %q;\n", r.Prefix.String(), r.Via)
		return
	}
	// No via and no blackhole: default to blackhole for safety.
	fmt.Fprintf(b, "    route %s blackhole;\n", r.Prefix.String())
}

// isBirdQuotedSymbol reports whether s can be emitted inside BIRD's
// apostrophe-quoted symbol syntax. Scoped next-hops use this syntax for
// interface names (for example, 192.0.2.1%'eth0').
func isBirdQuotedSymbol(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_', r == '-', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

func formatRouterID(id uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(id>>24)&0xff,
		(id>>16)&0xff,
		(id>>8)&0xff,
		id&0xff,
	)
}

// sanitizeNetNSName replaces non-alphanumeric characters in a netns name with
// underscores for use in BIRD identifiers (table/protocol/filter names).
func sanitizeNetNSName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		s = "netns"
	}
	return s
}

func defaultInternalTableName(netnsName string) string {
	return "photon_" + sanitizeNetNSName(netnsName)
}

// InternalRouteTableNames returns the BIRD IPv4 and IPv6 table names generated
// for a network namespace when no custom internal table name is configured.
// These tables are distinct from BIRD's default master tables.
func InternalRouteTableNames(netnsName string) []string {
	base := defaultInternalTableName(netnsName)
	return []string{base + "4", base + "6"}
}
