// gossip.js — peer cards + side detail panel (endpoints, diagnostics kv).

import * as store from '../store.js';
import { fetchAPI } from '../api.js';
import { navigate, renderCurrent } from '../router.js';
import { onItemInvalidate } from '../events.js';
import { esc, relTime, formatTime } from '../format.js';
import { pageHeader, filterInput, emptyState, loading, errorMsg } from '../components/card.js';
import { tableWrap, emptyRow } from '../components/table.js';
import { kvTable } from '../components/kv.js';
import { dot } from '../components/badge.js';

export const deps = ['/peers'];

// Detail cache keyed by selected peer; invalidated when /peers refetches.
let detail = { id: '', stamp: 0, data: null, error: null };

// peer_ids from the latest peer_updated payload. When the list refetch was
// triggered by peers that do not include the selected one, the cached detail
// is kept (item-level invalidation instead of a blanket detail refetch).
let peerHint = null;
onItemInvalidate((type, payload) => {
    if (type !== 'peer_updated') return;
    peerHint = payload ? (payload.peer_ids || (payload.peer_id ? [payload.peer_id] : null)) : null;
});

function kvFromObject(obj) {
    return Object.entries(obj || {}).map(([k, v]) => [
        k,
        `<code>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</code>`,
    ]);
}

function failureMessage(value) {
	return value && (value.message || value.code) || '';
}

function diagnostics(peer) {
	const rows = [];
	const lastFailure = failureMessage(peer.last_failure);
	if (lastFailure) rows.push(['Last Error', `<code>${esc(lastFailure)}</code>`]);
    if (peer.last_update_source) rows.push(['Update Source', esc(peer.last_update_source)]);
    if (peer.last_relay_suppression) rows.push(['Relay Suppression', esc(peer.last_relay_suppression)]);
    if (peer.observed_failure_count) rows.push(['Observed Failures', esc(peer.observed_failure_count)]);
    if (peer.datagram_stats) rows.push(...kvFromObject(peer.datagram_stats));
    if (peer.object_pull_stats) rows.push(...kvFromObject(peer.object_pull_stats));
    if (peer.rejected_digests && Object.keys(peer.rejected_digests).length) rows.push(...kvFromObject(peer.rejected_digests));
    if (!rows.length) return emptyState('No diagnostics recorded');
    return kvTable(rows);
}

function endpointTable(endpoints) {
    if (!endpoints || endpoints.length === 0) return emptyState('No endpoints');
    return tableWrap(`<table class="endpoint-table">
        <thead><tr><th>Addr</th><th>Source</th><th>Protocol</th><th>Scope</th><th>Priority</th><th>Last Observed</th><th>Selected</th></tr></thead>
        <tbody>${endpoints.map(ep => `
            <tr>
                <td><code>${esc(ep.addr || '-')}</code></td>
                <td>${esc(ep.source || '-')}</td>
                <td>${esc(ep.protocol || '-')}</td>
                <td>${esc(ep.scope || '-')}</td>
                <td>${ep.priority || 0}</td>
                <td>${relTime(ep.last_observed)}</td>
                <td>${ep.selected ? dot('up') : '-'}</td>
            </tr>`).join('')}</tbody>
    </table>`);
}

function detailPanel(route) {
    if (!route.selected) return emptyState('Select a peer to inspect endpoints and diagnostics');
    if (detail.error) return errorMsg(`Failed to load peer detail: ${detail.error.message}`);
    if (!detail.data) return loading('Loading peer detail…');
    const peer = detail.data;
    return `<section class="detail-panel">
        <h2>${esc(peer.peer_id)}</h2>
        ${kvTable([
            ['Source', esc(peer.source || '-')],
            ['Bootstrap Addr', `<code>${esc(peer.configured_addr || '-')}</code>`],
            ['Discovered Addr', `<code>${esc(peer.discovered_addr || '-')}</code>`],
            ['Observed Addr', `<code>${esc(peer.observed_addr || '-')}</code>`],
            ['Observed Window', `${formatTime(peer.observed_first_seen_unix)} → ${formatTime(peer.observed_until_unix)}`],
            ['Last Attempt', relTime(peer.last_attempt_unix)],
            ['Backoff Until', relTime(peer.backoff_until_unix)],
            ['Last Relay', relTime(peer.last_relay_unix)],
        ])}
        <h3>Endpoints</h3>
        ${endpointTable(peer.endpoints || [])}
        <h3>Diagnostics</h3>
        ${diagnostics(peer)}
    </section>`;
}

function ensureDetail(route) {
    if (!route.selected) return;
    const stamp = (store.get('/peers') || {}).updatedAt || 0;
    if (detail.id === route.selected && detail.stamp !== stamp && peerHint && !peerHint.includes(route.selected)) {
        // List refetched for unrelated peers; keep the cached detail.
        detail.stamp = stamp;
    }
    if (detail.id === route.selected && detail.stamp === stamp) return;
    peerHint = null;
    detail = { id: route.selected, stamp, data: null, error: null };
    fetchAPI(`/peers/${encodeURIComponent(route.selected)}`)
        .then(data => { detail.data = data; rerender(); })
        .catch(error => { detail.error = error; rerender(); });
}

function rerender() {
    renderCurrent();
}

export function render(container, route) {
    const header = pageHeader('Gossip', 'Peer exchange and discovery', filterInput(route, 'Filter peers…'));
    const entry = store.get('/peers');
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load peers: ${entry.error.message}`); return; }
    const filter = (route.filter || '').toLowerCase();
	const peers = (entry.data.peers || []).filter(p =>
        !filter || (p.peer_id || '').toLowerCase().includes(filter) || (p.source || '').toLowerCase().includes(filter));
	const cards = peers.map(p => {
		const lastFailure = failureMessage(p.last_failure);
		const status = lastFailure ? 'error' : (p.failure_count ? 'degraded' : 'up');
		const err = lastFailure ? ` · <span class="peer-err">${esc(lastFailure)}</span>` : '';
        return `<div class="peer-item${route.selected === p.peer_id ? ' selected' : ''}" data-peer="${esc(p.peer_id)}">
            ${dot(status)}
            <span class="peer-id">${esc(p.peer_id)}</span>
            <span class="peer-sub">${esc(p.source || '-')} · synced ${relTime(p.last_sync_unix)}${err}</span>
        </div>`;
    }).join('');
    container.innerHTML = `
        ${header}
        <div class="gossip-layout">
            <div class="peer-list">${cards || emptyState('No peers match')}</div>
            <div id="peer-detail">${detailPanel(route)}</div>
        </div>`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
    container.querySelectorAll('[data-peer]').forEach(card => {
        card.addEventListener('click', () => navigate('gossip', card.dataset.peer, route.filter));
    });
    ensureDetail(route);
}
