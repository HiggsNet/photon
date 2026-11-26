// zones.js — two-column layout: filterable zone list + selected zone detail.
// Debug material (authority / proofs / revocations / Raw JSON) lives in
// collapsed Inspect sections.

import * as store from '../store.js';
import { fetchAPI } from '../api.js';
import { renderCurrent } from '../router.js';
import { esc, copyable, compareZones } from '../format.js';
import { pageHeader, filterInput, emptyState, loading, errorMsg } from '../components/card.js';
import { kvTable } from '../components/kv.js';
import { jsonViewer } from '../components/jsonview.js';
import { dot, stateBadge } from '../components/badge.js';
import { recordTable, groupRecordsByKey } from '../components/records.js';
import { directoryRow, renderInspector, renderInspectorLoading } from '../components/inspector.js';

export const deps = ['/zones'];

let detail = { id: '', stamp: 0, data: null, error: null };

function zoneItem(z, selected) {
    return directoryRow(z.path, z.path, selected, `
        <span class="directory-status">${dot(z.revoked ? 'revoked' : 'healthy')}<span>${esc(z.path)}</span></span>
        <span class="directory-number">${esc(z.records || 0)}</span>`);
}

function inspectSection(summary, body) {
    return `<details class="record-details"><summary>${esc(summary)}</summary>${body}</details>`;
}

function jsonList(items) {
    if (!items || items.length === 0) return emptyState('No entries');
    return items.map(d => jsonViewer(d)).join('');
}

function zoneDetailPanel(selected) {
    if (!selected) return emptyState('Select a zone to inspect records and proofs');
    if (detail.error) return errorMsg(`Failed to load zone detail: ${detail.error.message}`);
    if (!detail.data) return loading('Loading zone detail…');
    const z = detail.data;
    const historyByKey = groupRecordsByKey(z.record_history || []);
    return `<section class="detail-panel zone-detail">
        <h2>${esc(z.path)}</h2>
        ${kvTable([
            ['Parent', esc(z.parent || '-')],
            ['Status', z.revoked ? stateBadge('revoked') : stateBadge('healthy')],
            ['Authority Hash', copyable(z.authority_hash)],
            ['Merkle Root', copyable(z.merkle_root)],
            ['Counts', esc(`${z.record_count || 0} records · ${z.history_count || 0} historical · ${z.delegation_count || 0} delegations · ${z.revocation_count || 0} revocations`)],
        ])}
        <h3>Active Records</h3>
        ${recordTable(z.records || [], historyByKey)}
        ${inspectSection(`Inspect · Authority`, jsonViewer(z.authority || {}))}
        ${inspectSection(`Inspect · Parent Proof (${(z.parent_proof || []).length})`, jsonList(z.parent_proof))}
        ${inspectSection(`Inspect · Delegations (${(z.delegations || []).length})`, jsonList(z.delegations))}
        ${inspectSection(`Inspect · Revocations (${(z.revocations || []).length})`, jsonList(z.revocations))}
        ${inspectSection('Inspect · Raw JSON', jsonViewer(z))}
    </section>`;
}

function ensureDetail(selected, stamp) {
    if (!selected || (detail.id === selected && detail.stamp === stamp)) return;
    const request = { id: selected, stamp, data: detail.id === selected ? detail.data : null, error: null };
    detail = request;
    // The root zone "." cannot be a URL path segment (ServeMux redirects it);
    // it is fetched via the ?zone= query form instead.
    const url = selected === '.' ? '/zones?zone=.' : `/zones/${encodeURIComponent(selected)}`;
    fetchAPI(url)
        .then(data => { if (detail === request) { request.data = data; renderCurrent(); } })
        .catch(error => { if (detail === request) { request.error = error; renderCurrent(); } });
}

export function render(container, route) {
    const entry = store.get('/zones');
    const root = entry?.data?.global_root;
    const header = pageHeader('Zones', '', `
        ${root ? `<div class="global-root"><span>Global Root</span>${copyable(root)}</div>` : ''}
        ${filterInput(route, 'Filter zones…')}`);
    if (!entry) return renderInspectorLoading(container, route.page, header);
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load zones: ${entry.error.message}`); return; }
    const filter = (route.filter || '').toLowerCase();
    const zones = (entry.data.zones || []).filter(z => !filter || (z.path || '').toLowerCase().includes(filter))
        .sort((a, b) => compareZones(a.path, b.path));
    const requested = (entry.data.zones || []).find(z => z.path === route.selected);
    const selection = requested?.path || zones[0]?.path || '';
    ensureDetail(selection, entry.updatedAt);
    renderInspector(container, route, {
        header, columns: ['Zone', 'Records'], empty: 'No zones match',
        list: zones.map(z => zoneItem(z, selection === z.path)).join(''),
        detail: zoneDetailPanel(selection), selection, openDetail: !!requested,
    });
}
