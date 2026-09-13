// health.js — data plane: probes, RTT/loss/jitter, history charts.
// Sparklines lazy-load on visibility; detail charts load per range. No N× amplification.

import * as store from '../store.js';
import { fetchAPI } from '../api.js';
import { navigate } from '../router.js';
import { onItemInvalidate } from '../events.js';
import { esc, ms, pct, relTime } from '../format.js';
import { pageHeader, filterInput, emptyState, loading, errorMsg } from '../components/card.js';
import { kvTable } from '../components/kv.js';
import { stateBadge, badge, dot } from '../components/badge.js';
import { sparkline } from '../components/chart.js';
import { historyPanel, bindHistory } from './health_history.js';

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

function severityOf(h) {
    if (!h) return '';
    if (h.state === 'down') return 'err';
    if (h.state && h.state !== 'healthy') return 'warn';
    return h.cutover_blocking ? 'warn' : '';
}

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

function linkRow(item, selected, showRole) {
    const h = healthValue(item) || {};
    return `<div class="link-item${selected ? ' selected' : ''}" data-link="${esc(probeID(item))}">
        ${dot(h.state || 'unknown')}
        <span class="link-zone">${esc(item.peer_zone || '-')}</span>
        <span class="link-family">${esc(item.group_id || '-')}</span>
        ${showRole ? roleBadge(h) : ''}
        ${stateBadge(h.state || 'unknown')}
    </div>`;
}

function detailPanel(item, datasource) {
    if (!item) return emptyState('Select a link to inspect probe state and history');
    const h = healthValue(item) || {};
	const desired = item.desired || {};
	const lastFailure = h.last_failure || {};
    const history = datasource && datasource.configured
        ? historyPanel(h.instance_id)
        : '<div class="muted">No local health history datasource configured.</div>';
    const probe = kvTable([
        ['Probe ID', `<code>${esc(h.probe_id || h.instance_id || '-')}</code>`],
        ['Role', esc(h.probe_role || 'active')],
        ['State', stateBadge(h.state)],
        ['Probe', esc(h.probe_type || '-')],
        ['Samples', esc(`${h.sent || 0} sent · ${h.received || 0} received · ${h.lost || 0} lost`)],
        ['Loss', pct(h.loss_ratio_pct)],
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
        <h2>${esc(probeID(item) || '-')} ${roleBadge(h)}</h2>
        <div class="detail-grid">
            <section><h3>Probe</h3>${probe}</section>
            <section><h3>Latency</h3>${latency}</section>
            <section><h3>Link</h3>${link}</section>
        </div>
        <section class="health-history-section"><h3>RTT History</h3>${history}</section>
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
    }, { root: document.getElementById('content') });
    slots.forEach(slot => observer.observe(slot));
}

export function render(container, route) {
    const header = pageHeader('Health · Data Plane', 'Probe state, latency and loss', filterInput(route, 'Filter links…'));
    const entry = store.get('/health');
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load health: ${entry.error.message}`); return; }
    const data = entry.data || {};
    const filter = (route.filter || '').toLowerCase();
    const rank = item => {
        const sev = severityOf(healthValue(item) || {});
        return sev === 'err' ? 0 : sev === 'warn' ? 1 : 2;
    };
    const links = (data.links || [])
        .filter(item => {
            const h = healthValue(item) || {};
            return !filter
                || (h.instance_id || '').toLowerCase().includes(filter)
                || (h.probe_id || '').toLowerCase().includes(filter)
                || (h.probe_role || '').toLowerCase().includes(filter)
                || (item.peer_zone || '').toLowerCase().includes(filter)
                || (item.group_id || '').toLowerCase().includes(filter);
        })
        .slice()
        .sort((a, b) => rank(a) - rank(b));
    // Select by probe id (unique per active/staged/old probe); fall back to
    // the active probe when a deep link carries only the link instance id.
    const selected = links.find(item => probeID(item) === route.selected)
        || links.find(item => {
            const h = healthValue(item) || {};
            return h.instance_id === route.selected && (!h.probe_role || h.probe_role === 'active');
        })
        || null;
    // Rotation: several probes share one instance id — mark each row's role.
    const instanceCount = new Map();
    links.forEach(item => {
        const id = (healthValue(item) || {}).instance_id || '';
        instanceCount.set(id, (instanceCount.get(id) || 0) + 1);
    });
    container.innerHTML = `
        ${header}
        <div class="overlay-layout">
            <div class="link-list">${links.map(item => linkRow(item, item === selected, instanceCount.get((healthValue(item) || {}).instance_id || '') > 1)).join('') || emptyState('No health data available')}</div>
            <div id="health-detail">${detailPanel(selected, data.datasource)}</div>
        </div>`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
    container.querySelectorAll('[data-link]').forEach(item => {
        item.addEventListener('click', () => navigate('health', item.dataset.link, route.filter));
    });
    setupSparklines(container);
    bindHistory(container, data.datasource);
}
