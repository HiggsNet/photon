// health.js — data plane: probes, RTT/loss/jitter, history charts.
// Sparklines lazy-load on visibility; detail charts load per range. No N× amplification.

import * as store from '../store.js';
import { fetchAPI } from '../api.js';
import { onItemInvalidate } from '../events.js';
import { esc, ms, pct, relTime, compareZones } from '../format.js';
import { pageHeader, filterInput, emptyState, errorMsg } from '../components/card.js';
import { kvTable } from '../components/kv.js';
import { stateBadge, badge, dot } from '../components/badge.js';
import { sparkline } from '../components/chart.js';
import { historyPanel, bindHistory } from './health_history.js';
import { directoryRow, linkDirectory, renderInspector, renderInspectorLoading, underlayLabel } from '../components/inspector.js';

export const deps = ['/health'];

// Sparkline series cache, invalidated per link when health_updated carries
// link_ids (item-level), cleared wholesale when it does not.
const sparkCache = new Map(); // instanceID -> values
onItemInvalidate((type, payload) => {
    if (type !== 'health_updated') return;
    const ids = payload && (payload.link_ids || (payload.link_id ? [payload.link_id] : null));
    if (!ids) {
        sparkCache.clear();
        return;
    }
    ids.forEach(id => sparkCache.delete(id));
});

function healthValue(item) { return item && item.health; }

// Rows are keyed by probe (probe_id), not link instance: during rotation a
// single instance_id has active/staged/old probes that must stay distinct.
function probeID(item) {
    const h = healthValue(item) || {};
    return h.probe_id || h.instance_id || '';
}

function roleBadge(h) {
    const role = h.probe_role || '';
    if (!role) return '';
    const tone = role === 'active' ? 'ok' : role === 'staged' ? 'warn' : 'unknown';
    return badge(role, tone);
}

function linkRow(item, selected, showRole, showGroup) {
    const h = healthValue(item) || {};
    const large = h.large_probe;
    const state = h.state || 'unknown';
    const family = underlayLabel(item);
    const familyColumn = family === 'IPv4' || family === 'IPv6';
    const probe = [h.probe_type, !familyColumn && family, showGroup && item.group_id].filter(Boolean).join(' · ');
    const rtt = h.last_rtt_ms > 0 ? ms(h.last_rtt_ms) : 'No RTT';
    const issue = h.last_failure || large?.last_failure;
    const problem = issue?.message || issue?.code || '';
    return directoryRow(probeID(item), probeID(item), selected, `
        <span class="directory-path">${showRole ? roleBadge(h) : ''}<span title="${esc(probe)}">${esc(probe || '–')}</span></span>
        <span class="directory-name directory-problem" title="${esc(problem)}">${esc(problem || '–')}</span>
        <span class="directory-status">${dot(state)}<span>${esc(state)}</span></span>
        <span class="directory-number">${h.sent > 0 ? pct(h.loss_ratio_pct) : '–'}</span>
        <span class="directory-number">${large && large.sent > 0 ? pct(Number(large.loss_ratio_pct).toFixed(1)) : '–'}</span>
        <span class="directory-number">${family === 'IPv4' ? rtt : '–'}</span>
        <span class="directory-number">${family === 'IPv6' ? rtt : '–'}</span>
    `);
}

function largeProbePanel(large) {
    if (!large) return '<div class="muted">Large-packet probing is disabled.</div>';
    const samples = large.sent > 0;
    return kvTable([
        ['Round-trip Loss', samples ? pct(Number(large.loss_ratio_pct).toFixed(1)) : 'Waiting for samples'],
        ['Last RTT', ms(large.last_rtt_ms)],
        ['Samples', esc(`${large.sent || 0} sent · ${large.received || 0} received · ${large.lost || 0} lost`)],
        ['Packet Size', `${esc(large.packet_size)} bytes (inner IP)`],
        ['Interval', `${esc(large.interval_seconds)}s · 1 packet per sample`],
        ['Window', `Latest ${esc(large.loss_window)} samples`],
        ['Last Probe', relTime(large.last_probe_unix)],
        ['Next Probe', relTime(large.next_probe_unix)],
        ['Last Error', `<code>${esc((large.last_failure || {}).message || '-')}</code>`],
    ]);
}

function detailPanel(item, datasource) {
    if (!item) return emptyState('Select a link to inspect probe state and history');
    const h = healthValue(item) || {};
	const desired = item.desired || {};
	const lastFailure = h.last_failure || {};
    const history = datasource && datasource.configured
        ? historyPanel(h.instance_id, !!h.large_probe)
        : '<div class="muted">No local health history datasource configured.</div>';
    const probe = kvTable([
        ['State', stateBadge(h.state)],
        ['Loss', h.sent > 0 ? pct(h.loss_ratio_pct) : 'Waiting for samples'],
        ['Samples', esc(`${h.sent || 0} sent · ${h.received || 0} received · ${h.lost || 0} lost`)],
        ['Probe ID', `<code>${esc(h.probe_id || h.instance_id || '-')}</code>`],
        ['Role', esc(h.probe_role || 'active')],
        ['Probe', esc(h.probe_type || '-')],
        ['Consecutive Failures', esc(h.consecutive_fail || 0)],
        ['Cutover Blocking', h.cutover_blocking ? 'Yes' : 'No'],
        ['Next Probe', relTime(h.next_probe_unix)],
		['Last Error', `<code>${esc(lastFailure.message || '-')}</code>`],
    ]);
    const latency = kvTable([
        ['Last RTT', ms(h.last_rtt_ms)], ['EWMA RTT', ms(h.ewma_rtt_ms)],
        ['P50 RTT', ms(h.p50_rtt_ms)], ['P95 RTT', ms(h.p95_rtt_ms)],
        ['P99 RTT', ms(h.p99_rtt_ms)], ['Jitter', ms(h.jitter_ms)],
        ['Trend (30m)', `<span class="sparkline-slot" data-instance="${esc(h.instance_id || '')}"><span class="muted">…</span></span>`],
    ]);
    const link = kvTable([
        ['Peer', esc(item.peer_zone || '-')],
        ['Group', esc(item.group_id || '-')],
        ['Interface', `<code>${esc(h.interface_name || item.interface_name || desired.interface_name || '-')}</code>`],
        ['Local Tunnel', `<code>${esc(item.local_tunnel_addr || desired.local_tunnel_addr || '-')}</code>`],
        ['Peer Tunnel', `<code>${esc(item.peer_tunnel_addr || desired.peer_tunnel_addr || '-')}</code>`],
        ['Endpoint', `<code>${esc(item.endpoint || desired.endpoint || '-')}</code>`],
    ]);
    return `<section class="detail-panel">
        <h2>${esc(item.peer_zone || '-')} · ${esc(underlayLabel(item))} ${roleBadge(h)}</h2>
        <div class="detail-grid">
            <section><h3>Small Packets</h3>${probe}</section>
            <section><h3>Latency</h3>${latency}</section>
            ${h.large_probe ? `<section><h3>Large Packets</h3>${largeProbePanel(h.large_probe)}</section>` : ''}
            <section><h3>Link</h3>${link}</section>
        </div>
        ${h.large_probe ? '' : largeProbePanel(null)}
        <section class="health-history-section"><h3>Probe History</h3>${history}</section>
    </section>`;
}

// Lazy sparklines: fetch a 30m series only when the card scrolls into
// view. Cache entries stay valid until the item-level invalidation above
// removes them, so list refetches no longer re-fetch every series.
function setupSparklines(root) {
    const load = async slot => {
        const id = slot.dataset.instance;
        if (!id) { slot.innerHTML = '<span class="muted">-</span>'; return; }
        const cached = sparkCache.get(id);
        if (cached) { slot.innerHTML = sparkline(cached); return; }
        try {
            const data = await fetchAPI(`/health/${encodeURIComponent(id)}/series?metric=rtt&range=30m&step=1m`);
            const points = (data.series && data.series.points) || [];
            const values = points.map(p => Number(p.value)).filter(v => Number.isFinite(v));
            sparkCache.set(id, values);
            if (slot.isConnected) slot.innerHTML = sparkline(values);
        } catch {
            sparkCache.set(id, []);
            if (slot.isConnected) slot.innerHTML = '<span class="muted">-</span>';
        }
    };
    const slots = root.querySelectorAll('.sparkline-slot[data-instance]');
    if (!('IntersectionObserver' in window)) { slots.forEach(load); return; }
    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) { observer.unobserve(entry.target); load(entry.target); }
        });
    }, { root: root.querySelector('.inspector-detail') });
    slots.forEach(slot => observer.observe(slot));
}

export function render(container, route) {
    const header = pageHeader('Health · Data Plane', '', filterInput(route, 'Filter links…'));
    const entry = store.get('/health');
    if (!entry) return renderInspectorLoading(container, route.page, header);
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load health: ${entry.error.message}`); return; }
    const data = entry.data || {};
    const filter = (route.filter || '').toLowerCase();
    const links = (data.links || [])
        .filter(item => {
            const h = healthValue(item) || {};
            return !filter
                || (h.instance_id || '').toLowerCase().includes(filter)
                || (h.probe_id || '').toLowerCase().includes(filter)
                || (h.probe_role || '').toLowerCase().includes(filter)
                || underlayLabel(item).toLowerCase().includes(filter)
                || (item.peer_zone || '').toLowerCase().includes(filter)
                || (item.group_id || '').toLowerCase().includes(filter);
        })
        .slice()
        .sort((a, b) => compareZones(a.peer_zone, b.peer_zone)
            || String(a.group_id || '').localeCompare(String(b.group_id || ''))
            || underlayLabel(a).localeCompare(underlayLabel(b))
            || String((healthValue(a) || {}).instance_id || '').localeCompare(String((healthValue(b) || {}).instance_id || ''))
            || roleOrder(healthValue(a)) - roleOrder(healthValue(b))
            || probeID(a).localeCompare(probeID(b)));
    // Select by probe id (unique per active/staged/old probe); fall back to
    // the active probe when a deep link carries only the link instance id.
    const requested = links.find(item => probeID(item) === route.selected)
        || links.find(item => {
            const h = healthValue(item) || {};
            return h.instance_id === route.selected && (!h.probe_role || h.probe_role === 'active');
        });
    const selected = requested || links[0];
    // Rotation: several probes share one instance id — mark each row's role.
    const instanceCount = new Map();
    (data.links || []).forEach(item => {
        const id = (healthValue(item) || {}).instance_id || '';
        instanceCount.set(id, (instanceCount.get(id) || 0) + 1);
    });
    const list = linkDirectory(links, (item, showGroup) => {
        const h = healthValue(item) || {};
        const showRole = h.probe_role && (h.probe_role !== 'active' || instanceCount.get(h.instance_id) > 1);
        return linkRow(item, item === selected, showRole, showGroup);
    });
    renderInspector(container, route, {
        header, columns: ['Probe', 'Problem', 'State', 'Small loss', 'Large loss', 'IPv4 RTT', 'IPv6 RTT'],
        list, empty: 'No health data available',
        detail: detailPanel(selected, data.datasource), selection: probeID(selected), openDetail: !!requested,
    });
    setupSparklines(container);
    bindHistory(container, data.datasource);
}

function roleOrder(h) {
    return ({ active: 0, old: 1, staged: 2 })[(h || {}).probe_role || 'active'] ?? 3;
}
