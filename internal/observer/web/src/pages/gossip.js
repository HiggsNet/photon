// gossip.js — peer cards + side detail panel (endpoints, diagnostics kv).

import * as store from '../store.js';
import { esc, relTime, formatTime, compareZones } from '../format.js';
import { pageHeader, filterInput, emptyState, errorMsg } from '../components/card.js';
import { tableWrap } from '../components/table.js';
import { kvTable } from '../components/kv.js';
import { dot } from '../components/badge.js';
import { directoryGroup, directoryGroups, directoryRow, renderInspector, renderInspectorLoading } from '../components/inspector.js';

export const deps = ['/peers'];

function lastSuccess(peer) {
    return peer.last_sync_unix ? new Date(peer.last_sync_unix * 1000).toISOString().slice(0, 19) + 'Z' : 'never';
}

function parentZone(id) {
    const separator = id.indexOf('.');
    return separator > 0 ? id.slice(separator + 1) || '.' : '.';
}

function peerRow(peer, selected) {
    const status = peer.sync_status || 'unknown';
    const name = peer.peer_id.split('.')[0] || peer.peer_id;
    return directoryRow(peer.peer_id, peer.peer_id, peer === selected, `
        <span class="directory-name">${esc(name)}</span>
        <span class="directory-status">${dot(status)}<span>${esc(status.replaceAll('_', ' '))}</span></span>
        <span class="directory-number">${peer.last_sync_unix ? relTime(peer.last_sync_unix) : 'Never'}</span>
    `);
}

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

function detailPanel(peer) {
    if (!peer) return emptyState('Select a peer to inspect endpoints and diagnostics');
    return `<section class="detail-panel">
        <h2>${esc(peer.peer_id)}</h2>
        ${kvTable([
            ['Sync Status', esc(peer.sync_status)],
            ['Last Success', esc(lastSuccess(peer))],
            ['Authorization', esc(peer.authorization)],
            ['Session Phase', esc(peer.active_pull_state || '-')],
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

export function render(container, route) {
    const header = pageHeader('Gossip', '', filterInput(route, 'Filter peers…'));
    const entry = store.get('/peers');
    if (!entry) return renderInspectorLoading(container, route.page, header);
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load peers: ${entry.error.message}`); return; }
    const filter = (route.filter || '').toLowerCase();
    const allPeers = (entry.data.peers || [])
        .filter(p => p.sync_status !== 'revoked' && p.authorization !== 'revoked')
        .sort((a, b) => compareZones(a.peer_id, b.peer_id));
    const peers = allPeers.filter(p =>
        !filter || (p.peer_id || '').toLowerCase().includes(filter) || (p.source || '').toLowerCase().includes(filter));
    const requested = allPeers.find(p => p.peer_id === route.selected);
    const selected = requested || peers[0];
    const list = directoryGroups(peers, p => parentZone(p.peer_id), (zone, group) =>
        directoryGroup(zone === '.' ? 'Root zone' : zone, group.map(p => peerRow(p, selected)).join('')));
    const selection = selected?.peer_id || '';
    renderInspector(container, route, {
        header, columns: ['Peer', 'Status', 'Last sync'], list, empty: 'No peers match',
        detail: detailPanel(selected), selection, openDetail: !!requested,
    });
}
