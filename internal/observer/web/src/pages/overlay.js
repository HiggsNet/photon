// overlay.js — control plane: planner desired vs actual, IKE/Child SA,
// reconcile actions/skipped, rotation/takeover. Data-plane probing lives
// on the Health page; this page only links there.
// Layout: narrow dense link list (sorted by peer zone) + side detail panel.

import * as store from '../store.js';
import { navigate } from '../router.js';
import { esc, relTime, copyable, compareZones } from '../format.js';
import { pageHeader, filterInput, emptyState, loading, errorMsg } from '../components/card.js';
import { kvTable } from '../components/kv.js';
import { jsonViewer } from '../components/jsonview.js';
import { stateBadge, dot } from '../components/badge.js';

export const deps = ['/links'];

function desiredValue(link) { return (link && link.desired) || {}; }
function actualSAValue(link) { return (link && link.actual_sa) || {}; }

function linkRow(li, selected) {
    const state = li.state || li.actual_state || '';
    return `<div class="link-item${selected ? ' selected' : ''}" data-link="${esc(li.id || '')}">
        ${dot(state || 'unknown')}
        <span class="link-zone">${esc(li.peer_zone || '-')}</span>
        <span class="link-family">${esc(li.group_id || '-')}</span>
        ${stateBadge(state || 'unknown')}
    </div>`;
}

function detailPanel(li) {
    if (!li) return emptyState('Select a link to inspect planner, SA and rotation state');
    const desired = desiredValue(li);
    const sa = actualSAValue(li);
    const routing = li.routing || {};
    const rotation = li.rotation || {};
    const takeover = li.takeover || {};
    const state = li.state || li.actual_state || '';
    const iface = li.interface_name || desired.interface_name || '-';
    const ifId = li.xfrm_if_id || desired.xfrm_if_id || '-';
	const healthID = (li.health && li.health.instance_id) || '';
    return `<section class="detail-panel">
        <h2>${esc(li.id || '-')}</h2>
        ${kvTable([
            ['Peer', `${esc(li.peer_zone || '-')} · ${esc(li.group_id || '-')}`],
            ['State', stateBadge(state || 'unknown')],
            ['Interface', `<code>${esc(iface)}</code> <span class="muted">if_id ${esc(ifId)}</span>`],
            ['Endpoint', `<code>${esc(li.endpoint || desired.endpoint || '-')}</code>`],
            ['SA', stateBadge(sa.established ? 'established' : (sa.child_state || sa.ike_state || '-'))],
            ['Rotate', esc(rotation.phase || 'idle')],
            ['Failures', esc(li.failure_count || 0)],
            ['Health', `<a href="#/health/${encodeURIComponent(healthID)}">data plane →</a>`],
        ])}
        <div class="inspect-grid">
            <section>
                <h3>Planner</h3>
                ${kvTable([
                    ['Desired Hash', copyable(desired.desired_spec_hash || li.desired_spec_hash)],
                    ['Endpoint', `<code>${esc(desired.endpoint || li.endpoint || '-')}</code>`],
                    ['Local Tunnel', `<code>${esc(desired.local_tunnel_addr || '-')}</code>`],
                    ['Peer Tunnel', `<code>${esc(desired.peer_tunnel_addr || '-')}</code>`],
                ])}
            </section>
            <section>
                <h3>StrongSwan</h3>
                ${kvTable([
                    ['IKE', `<code>${esc(li.ike_name || sa.name || '-')}</code>`],
                    ['Child SA', `<code>${esc(sa.child_sa || '-')}</code>`],
                    ['SA State', stateBadge(sa.established ? 'established' : (sa.child_state || sa.ike_state || '-'))],
                    ['ReqID', esc(sa.reqid || '-')],
                    ['Observed if_id', esc(sa.xfrm_if_id || '-')],
                    ['Local Endpoint', `<code>${esc(sa.local_endpoint || '-')}</code>`],
                    ['Remote Endpoint', `<code>${esc(sa.remote_endpoint || sa.endpoint || '-')}</code>`],
                    ['Local Identity', `<code>${esc(sa.local_identity || '-')}</code>`],
                    ['Remote Identity', `<code>${esc(sa.remote_identity || '-')}</code>`],
                ])}
            </section>
            <section>
                <h3>Routing</h3>
                ${kvTable([
                    ['BIRD State', stateBadge(routing.bird_state || '-')],
                    ['Neighbors', esc(routing.bird_neighbors || '-')],
                    ['Best Routes', esc(routing.bird_best_routes || '-')],
                ])}
            </section>
            <section>
                <h3>Rotation</h3>
                ${kvTable([
                    ['Phase', esc(rotation.phase || 'idle')],
                    ['Remote Generation', esc(rotation.remote_generation || 0)],
                    ['Staged Generation', esc(rotation.staged_generation || 0)],
                    ['Staged IKE', `<code>${esc(rotation.staged_ike_name || '-')}</code>`],
                    ['Staged Child', `<code>${esc(rotation.staged_child_sa_name || '-')}</code>`],
                    ['Staged Interface', `<code>${esc(rotation.staged_interface_name || '-')}</code>`],
                    ['Deadline', relTime(rotation.rotate_deadline)],
                ])}
            </section>
            <section>
                <h3>Takeover</h3>
                ${kvTable([
                    ['Initiator Role', esc(takeover.initiator_role || '-')],
                    ['Phase', esc(takeover.phase || '-')],
                    ['Until', relTime(takeover.until)],
                    ['Observed Initiator', `<code>${esc(takeover.observed_initiator || '-')}</code>`],
					['Last Error', `<code>${esc((takeover.last_failure || {}).message || '-')}</code>`],
                ])}
            </section>
        </div>
        <details class="record-details"><summary>Raw JSON</summary>${jsonViewer(li)}</details>
    </section>`;
}

function actionTable(actions) {
    if (!actions || actions.length === 0) return emptyState('No actions');
    return `<table class="mini-table">
        <tr><th>Action</th><th>Link ID</th><th>Peer</th><th>Group</th><th>Reason</th></tr>
        ${actions.map(a => `
            <tr>
                <td>${stateBadge(a.action || '-')}</td>
                <td><code>${esc(a.instance_id || '-')}</code></td>
                <td>${esc(a.peer_zone || '-')}</td>
                <td>${esc(a.group_id || '-')}</td>
                <td>${esc(a.reason || '-')}</td>
            </tr>`).join('')}
    </table>`;
}

function skippedTable(skipped) {
    if (!skipped || skipped.length === 0) return emptyState('No skipped items');
    return `<table class="mini-table">
        <tr><th>Group</th><th>Peer</th><th>Reason</th><th>Detail</th></tr>
        ${skipped.map(s => `
            <tr>
                <td>${esc(s.group_id || '-')}</td>
                <td>${esc(s.peer || '-')}</td>
                <td>${stateBadge(s.reason || '-')}</td>
                <td>${esc(s.detail || '-')}</td>
            </tr>`).join('')}
    </table>`;
}

export function render(container, route) {
    const header = pageHeader('Overlay · Control Plane', 'Planner, SAs and reconcile', filterInput(route, 'Filter links…'));
    const entry = store.get('/links');
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load links: ${entry.error.message}`); return; }
    const data = entry.data || {};
    const filter = (route.filter || '').toLowerCase();
    const instances = (data.instances || []).filter(li => !filter
        || (li.id || '').toLowerCase().includes(filter)
        || (li.peer_zone || '').toLowerCase().includes(filter)
        || (li.group_id || '').toLowerCase().includes(filter));
    instances.sort((a, b) => compareZones(b.peer_zone, a.peer_zone)
        || String(a.id || '').localeCompare(String(b.id || '')));
    const selected = instances.find(li => li.id === route.selected) || null;
    container.innerHTML = `
        ${header}
        <div class="overlay-layout">
            <div class="link-list">${instances.map(li => linkRow(li, li.id === route.selected)).join('') || emptyState('No link instances match')}</div>
            <div id="link-detail">${detailPanel(selected)}</div>
        </div>
        <h2>Reconcile</h2>
        ${kvTable([
            ['Last Run', relTime(data.last_run_unix)],
            ['Desired Links', esc(data.desired_links || 0)],
            ['Actual SAs', esc(data.actual_sas || 0)],
			['Last Error', `<code>${esc((data.last_failure || {}).message || '-')}</code>`],
        ])}
        <details class="record-details"><summary>Actions (${(data.actions || []).length})</summary>${actionTable(data.actions)}</details>
        <details class="record-details"><summary>Skipped (${(data.skipped || []).length})</summary>${skippedTable(data.skipped)}</details>`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
    container.querySelectorAll('[data-link]').forEach(item => {
        item.addEventListener('click', () => navigate('overlay', item.dataset.link, route.filter));
    });
}
