// overview.js — dashboard: "is there a problem right now?"

import * as store from '../store.js';
import { esc, relTime, copyable } from '../format.js';
import { pageHeader, statCard, banner, loading, errorMsg } from '../components/card.js';
import { kvTable } from '../components/kv.js';
import { dot } from '../components/badge.js';

export const deps = ['/status', '/links', '/health', '/zones'];

function collectIssues(status, links, healthLinks, zones) {
    const issues = [];
    for (const li of links) {
        const state = li.state || li.actual_state || '';
        if (state && state !== 'up') {
            issues.push({
                tone: 'err',
                target: li.id || 'link',
                summary: `link ${state} (peer ${li.peer_zone || '-'})`,
                href: '#/overlay',
            });
        }
    }
	for (const item of healthLinks) {
		const h = item.health || {};
		const failure = h.last_failure || {};
		if (h.state && h.state !== 'healthy') {
            issues.push({
                tone: h.state === 'down' ? 'err' : 'warn',
                target: h.instance_id || 'link',
				summary: `health ${h.state}${failure.message ? ` — ${failure.message}` : ''}`,
                href: `#/health/${encodeURIComponent(h.instance_id || '')}`,
            });
        }
        if (h.cutover_blocking) {
            issues.push({ tone: 'warn', target: h.instance_id || 'link', summary: 'cutover blocking', href: '#/health' });
        }
    }
    for (const z of zones) {
        if (z.revoked) {
            issues.push({ tone: 'err', target: z.path, summary: 'zone revoked', href: `#/zones/${encodeURIComponent(z.path)}` });
        }
    }
	if (status.last_link_failure) {
		issues.push({ tone: 'err', target: 'reconcile', summary: status.last_link_failure.message || status.last_link_failure.code, href: '#/overlay' });
	}
	if (status.last_routing_failure) {
		issues.push({ tone: 'err', target: 'routing', summary: status.last_routing_failure.message || status.last_routing_failure.code, href: '#/bird' });
    }
    return issues.slice(0, 10);
}

export function render(container) {
    const header = pageHeader('Overview', 'Node status at a glance');
    const statusEntry = store.get('/status');
    if (!statusEntry) {
        container.innerHTML = header + loading();
        return;
    }
    if (statusEntry.error && !statusEntry.data) {
        container.innerHTML = header + errorMsg(`Failed to load status: ${statusEntry.error.message}`);
        return;
    }
    const s = statusEntry.data || {};
    const links = (store.get('/links') && store.get('/links').data && store.get('/links').data.instances) || [];
    const healthLinks = (store.get('/health') && store.get('/health').data && store.get('/health').data.links) || [];
    const zones = (store.get('/zones') && store.get('/zones').data && store.get('/zones').data.zones) || [];

    const issues = collectIssues(s, links, healthLinks, zones);
    const linksUp = links.filter(li => (li.state || li.actual_state) === 'up').length;

    const bannerHTML = issues.length === 0
        ? banner('All systems normal', 'ok')
        : banner(`${issues.length} issue${issues.length === 1 ? '' : 's'} need attention`, issues.some(i => i.tone === 'err') ? 'err' : 'warn');
    const issueList = issues.length === 0 ? '' : `
        <div class="issue-list">
            ${issues.map(i => `<div class="issue-row">
                ${dot(i.tone === 'err' ? 'down' : 'degraded')}
                <span class="issue-target">${esc(i.target)}</span>
                <span class="issue-summary">${esc(i.summary)}</span>
                <a href="${esc(i.href)}">Inspect →</a>
            </div>`).join('')}
        </div>`;

    container.innerHTML = `
        ${header}
        ${bannerHTML}
        ${issueList}
        <div class="stat-grid">
            ${statCard('Zones', s.known_zones || 0)}
            ${statCard('Peers', s.known_peers || 0)}
            ${statCard('Links', `${linksUp}/${links.length || s.link_instances || 0}`, 'up / total')}
            ${statCard('Desired Links', s.desired_links || 0)}
        </div>
        <h2>Node</h2>
        ${kvTable([
            ['Peer ID', copyable(s.peer_id, s.peer_id || '-')],
            ['Managed Zone', esc(s.managed_zone || '-')],
            ['Listen Addr', `<code>${esc(s.listen_addr || '-')}</code>`],
            ['Last Sync', relTime(s.last_sync_unix)],
            ['Last Reconcile', relTime(s.last_reconcile_unix)],
            ['Snapshot', esc(`${s.known_zones || 0} zones · ${s.known_peers || 0} peers · ${s.link_instances || 0} link instances`)],
        ])}`;
}
