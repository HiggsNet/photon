package text

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteFirewall(w io.Writer, view inspect.FirewallDebugView, filter string, verbose bool) error {
	if len(view.Instances) == 0 {
		out := newLineWriter(w)
		out.Println("firewall: not configured")
		return out.Err()
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	instances := make([]inspect.FirewallInstanceView, 0, len(view.Instances))
	for _, instance := range view.Instances {
		services := firewallServiceList(instance.LocalServices)
		searchable := strings.Join([]string{
			instance.ID,
			instance.Scope,
			instance.Mode,
			instance.Backend,
			instance.ResolvedBackend,
			instance.LastError,
			instance.DefaultPolicy,
			strings.Join(instance.AllowFilters, " "),
			strings.Join(instance.DenyFilters, " "),
			strings.Join(instance.AllowPeers, " "),
			strings.Join(instance.DenyPeers, " "),
			strings.Join(services, " "),
		}, " ")
		if filter == "" || strings.Contains(strings.ToLower(searchable), filter) {
			instances = append(instances, instance)
		}
	}

	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	if view.LastFailure != nil {
		out.Println("firewall: error")
	} else {
		out.Println("firewall: active")
	}
	out.LineIf(view.Backend != "", "backend: %s", view.Backend)
	out.Linef("instances: %s", filteredCount(len(instances), len(view.Instances), filter))
	if verbose {
		out.Println("INSTANCE\tSCOPE\tMODE\tBACKEND\tSTATUS\tDEFAULT\tTRANSIT\tPREFIX_FILTERS\tPEER_FILTERS\tMETRIC\tSERVICES\tGENERATION\tOBJECTS")
	} else {
		out.Println("INSTANCE\tSCOPE\tMODE\tBACKEND\tSTATUS")
	}
	for _, instance := range instances {
		backend := defaultText(instance.ResolvedBackend, defaultText(instance.Backend, "auto"))
		if verbose {
			out.Linef("%s\t%s\t%s\t%s\t%s\t%s\t%t\t%d/%d\t%d/%d\t%d\t%d\t%d\t%d",
				instance.ID,
				defaultText(instance.Scope, "-"),
				defaultText(instance.Mode, "managed"),
				backend,
				firewallInstanceStatus(instance),
				defaultText(instance.DefaultPolicy, "drop"),
				instance.Transit,
				instance.AllowPrefixes,
				instance.DenyPrefixes,
				len(instance.AllowPeers),
				len(instance.DenyPeers),
				instance.MetricHint,
				len(instance.LocalServices),
				instance.Generation,
				instance.OwnedObjects,
			)
		} else {
			out.Linef("%s\t%s\t%s\t%s\t%s",
				instance.ID,
				defaultText(instance.Scope, "-"),
				defaultText(instance.Mode, "managed"),
				backend,
				firewallInstanceStatus(instance),
			)
		}
	}
	if failure := view.LastFailure; failure != nil {
		out.Linef("last_failure: code=%s message=%s", failure.Code, failure.Message)
	}
	if err := out.Err(); err != nil {
		return err
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if !verbose {
		return nil
	}

	detail := newLineWriter(w)
	for _, instance := range instances {
		detail.Blank()
		detail.Linef("instance: %s", instance.ID)
		detail.Linef("  transit_policy: enabled=%t default=%s", instance.Transit, defaultText(instance.DefaultPolicy, "drop"))
		detail.Linef("  allow_filters: %s", joinedOrDash(instance.AllowFilters))
		detail.Linef("  deny_filters: %s", joinedOrDash(instance.DenyFilters))
		detail.Linef("  allow_peers: %s", joinedOrDash(instance.AllowPeers))
		detail.Linef("  deny_peers: %s", joinedOrDash(instance.DenyPeers))
		detail.Linef("  metric_hint: %d", instance.MetricHint)
		detail.Linef("  local_services: %s", joinedOrDash(firewallServiceList(instance.LocalServices)))
		if instance.IsHost {
			detail.Linef("  host_ports: ike=%t natt=%t redirect_grace=%t", instance.HostIKE, instance.HostNATT, instance.RedirectGrace)
		}
		detail.Linef("  owner_prefix: %s", dash(instance.OwnerPrefix))
		detail.LineIf(instance.LastError != "", "  last_error: %s", instance.LastError)
	}
	return detail.Err()
}

func firewallServiceList(services []inspect.FirewallLocalServiceView) []string {
	out := make([]string, 0, len(services))
	for _, service := range services {
		out = append(out, fmt.Sprintf("%s/%d", service.Proto, service.Port))
	}
	return out
}

func joinedOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ", ")
}

func firewallInstanceStatus(instance inspect.FirewallInstanceView) string {
	switch {
	case instance.LastError != "":
		return "error"
	case instance.Mode == "disabled":
		return "disabled"
	case instance.ResolvedBackend != "":
		return "active"
	default:
		return "pending"
	}
}

func WriteDebugFirewall(w io.Writer, view inspect.FirewallDebugView) error {
	out := newLineWriter(w)
	if len(view.Instances) == 0 {
		out.Linef("firewall: not configured")
		return out.Err()
	}
	out.LineIf(view.Backend != "", "backend: %s", view.Backend)
	if failure := view.LastFailure; failure != nil {
		out.Linef("last_reconcile_failure: code=%s message=%s", failure.Code, failure.Message)
	}
	for _, inst := range view.Instances {
		out.Linef("instance %s", inst.ID)
		out.Linef("  scope: %s", inst.Scope)
		out.Linef("  mode: %s", inst.Mode)
		out.Linef("  backend: %s", defaultText(inst.Backend, "auto"))
		out.LineIf(inst.ResolvedBackend != "", "  resolved_backend: %s", inst.ResolvedBackend)
		out.Linef("  default_policy: %s", defaultText(inst.DefaultPolicy, "drop"))
		out.LineIf(inst.OwnerPrefix != "", "  owner_prefix: %s", inst.OwnerPrefix)
		out.Linef("  transit: %t", inst.Transit)
		out.LineIf(inst.AllowPrefixes > 0, "  allow_prefixes: %d", inst.AllowPrefixes)
		out.LineIf(inst.DenyPrefixes > 0, "  deny_prefixes: %d", inst.DenyPrefixes)
		if len(inst.LocalServices) > 0 {
			out.Linef("  local_services: %d", len(inst.LocalServices))
			for _, svc := range inst.LocalServices {
				out.Linef("    %s/%d", svc.Proto, svc.Port)
			}
		}
		if inst.IsHost {
			out.Linef("  host_ports: ike=%t natt=%t", inst.HostIKE, inst.HostNATT)
			out.Linef("  redirect_grace: %t", inst.RedirectGrace)
		}
		if len(inst.InlineHooks) > 0 {
			out.Linef("  inline_hooks: %d", len(inst.InlineHooks))
			for _, hook := range inst.InlineHooks {
				backend := hook.Backend
				if hook.Family != "" {
					backend += "/" + hook.Family
				}
				out.Linef("    [%s] %s %s: %s", defaultText(hook.State, "pending"), backend, hook.Point, hook.Expression)
			}
		}
		out.LineIf(inst.Generation != 0, "  generation: %d", inst.Generation)
		out.LineIf(inst.OwnedObjects != 0, "  owned_objects: %d", inst.OwnedObjects)
		out.LineIf(inst.PolicyHash != "", "  policy_hash: %s", inst.PolicyHash)
		out.LineIf(inst.LastError != "", "  last_error: %s", inst.LastError)
	}
	return out.Err()
}
