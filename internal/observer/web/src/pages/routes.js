// routes.js — URL-addressable views of authorized routes, IPAM and errors.

import * as store from '../store.js';
import { navigate } from '../router.js';
import { esc, comparePrefixes, compareZones } from '../format.js';
import { pageHeader, filterInput, banner, emptyState, loading, errorMsg } from '../components/card.js';
import { tableWrap, emptyRow } from '../components/table.js';
import { stateBadge } from '../components/badge.js';

export const deps = ['/routes'];

const tabs = new Map([
    ['authorized', 'Authorized routes'],
    ['ipam', 'IPAM'],
    ['errors', 'Authorization errors'],
]);

function routeTabs(selected, filter, errorCount) {
    const query = filter ? `?f=${encodeURIComponent(filter)}` : '';
    return `<nav class="route-tabs" aria-label="Route views">${Array.from(tabs, ([key, label]) => `
        <a href="#/routes/${key}${esc(query)}"${key === selected ? ' aria-current="page"' : ''}>
            ${label}${key === 'errors' && errorCount ? ` <span class="badge badge-err">${errorCount}</span>` : ''}
        </a>`).join('')}</nav>`;
}

function errorsSection(errors) {
    if (!errors.length) {
        return `<h2>Authorization Errors (0)</h2>${emptyState('No authorization errors')}`;
    }
    return `<section class="section-errors">
        <h2>Authorization Errors (${errors.length})</h2>
        ${tableWrap(`<table class="routes-table">
            <thead><tr><th>Prefix</th><th class="zone-column">Zone</th><th>Code</th><th>Detail</th></tr></thead>
            <tbody>${errors.map(e => `
                <tr><td><code>${esc(e.prefix || '-')}</code></td><td class="zone-column">${esc(e.zone)}</td><td>${esc(e.code)}</td><td>${esc(e.detail)}</td></tr>`).join('')}</tbody>
        </table>`)}
    </section>`;
}

function groupSharedAssignments(assignments) {
    const groups = new Map();
    for (const assignment of assignments.filter(item => item.shared)) {
        const prefix = assignment.prefix || '';
        if (!groups.has(prefix)) groups.set(prefix, []);
        groups.get(prefix).push(assignment);
    }
    return [...groups.entries()]
        .map(([prefix, members]) => ({
            prefix,
            members: members.slice().sort((a, b) => compareZones(a.assigned_to, b.assigned_to)),
        }))
        .sort((a, b) => comparePrefixes(a.prefix, b.prefix));
}

function participantList(members) {
    return `<div class="route-participants">${members.map(member => `
        <div class="route-participant">
            <span class="zone-value">${esc(member.assigned_to || '-')}</span>
            ${member.source && member.source !== member.assigned_to ? `<span class="muted">via ${esc(member.source)}</span>` : ''}
            ${member.tag ? `<span class="chip">${esc(member.tag)}</span>` : ''}
        </div>`).join('')}</div>`;
}

export function render(container, route) {
    const entry = store.get('/routes');
    const data = entry?.data || {};
    const selected = tabs.has(route.selected) ? route.selected : 'authorized';
    const header = pageHeader('Routes', '', filterInput(route, 'Filter by zone / prefix…'))
        + routeTabs(selected, route.filter, data.errors?.length || 0);
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load routes: ${entry.error.message}`); return; }
    const filter = (route.filter || '').toLowerCase();
    const match = (...fields) => !filter || fields.some(f => (f || '').toLowerCase().includes(filter));

    const errors = data.errors || [];
    const errorBanner = errors.length && selected !== 'errors'
        ? banner(`${errors.length} authorization error${errors.length === 1 ? '' : 's'}`, 'err')
        : '';
    const body = selected === 'authorized' ? authorizedSection(data, match)
        : selected === 'ipam' ? ipamSection(data, match)
        : errorsSection(errors.filter(e => match(e.prefix, e.zone, e.code, e.detail))
            .sort((a, b) => comparePrefixes(a.prefix, b.prefix) || compareZones(a.zone, b.zone)));
    container.innerHTML = header + errorBanner + body;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
}

function allAssignments(data) {
    return data.ipam_assignments || Object.entries(data.assignments || {}).map(([prefix, info]) => ({
        prefix,
        source: info.source,
        assigned_to: info.assigned_to,
    }));
}

function authorizedSection(data, match) {
    const exportSet = (data.export_set || []).filter(p => match(p)).sort(comparePrefixes);
    const authorized = Object.entries(data.authorized || {}).filter(([zone, prefixes]) =>
        match(zone, ...(prefixes || [])))
        .sort(([a], [b]) => compareZones(a, b));
    const authorizedRoutes = (data.authorized_routes || authorized.flatMap(([zone, prefixes]) =>
        (prefixes || []).map(prefix => ({ prefix, zone }))));
    const sharedAuthorizedGroups = data.shared_authorized || {};
    const sharedPrefixes = new Set(Object.keys(sharedAuthorizedGroups));
    if (!sharedPrefixes.size) {
        for (const assignment of allAssignments(data).filter(a => a.shared)) sharedPrefixes.add(assignment.prefix);
    }
    const nonSharedAuthorized = authorizedRoutes.filter(item => !item.shared && !sharedPrefixes.has(item.prefix) && match(item.prefix, item.zone, item.tag))
        .sort((a, b) => comparePrefixes(a.prefix, b.prefix) || compareZones(a.zone, b.zone));
    const sharedAuthorizedByPrefix = new Map();
    for (const item of authorizedRoutes.filter(item => (item.shared || sharedPrefixes.has(item.prefix)) && match(item.prefix, item.zone, item.tag))) {
        if (!sharedAuthorizedByPrefix.has(item.prefix)) sharedAuthorizedByPrefix.set(item.prefix, []);
        sharedAuthorizedByPrefix.get(item.prefix).push({ assigned_to: item.zone, tag: item.tag });
    }
    const sharedAuthorized = [...sharedAuthorizedByPrefix.entries()]
        .map(([prefix, members]) => ({ prefix, members: members.sort((a, b) => compareZones(a.assigned_to, b.assigned_to)) }))
        .sort((a, b) => comparePrefixes(a.prefix, b.prefix));
    return `
        <h2>Local Export Set</h2>
        <div>${exportSet.map(p => `<span class="chip">${esc(p)}</span>`).join('') || emptyState('No exports')}</div>
        <h2>Non-shared Authorized Prefixes by Zone</h2>
        ${tableWrap(`<table class="routes-table">
            <thead><tr><th>Prefix</th><th class="zone-column">Zone</th><th>Tag</th></tr></thead>
            <tbody>${nonSharedAuthorized.map(item => `
                <tr><td><code>${esc(item.prefix || '-')}</code></td><td class="zone-column">${esc(item.zone || '-')}</td><td>${esc(item.tag || '-')}</td></tr>`).join('') || emptyRow(3)}</tbody>
        </table>`)}
        <h2>Shared Authorized Prefixes</h2>
        ${tableWrap(`<table class="routes-table">
            <thead><tr><th>Prefix</th><th>Participating Nodes</th></tr></thead>
            <tbody>${sharedAuthorized.map(group => `
                <tr><td><code>${esc(group.prefix || '-')}</code></td><td>${participantList(group.members)}</td></tr>`).join('') || emptyRow(2)}</tbody>
        </table>`)}`;
}

function ipamSection(data, match) {
    const pools = (data.ipam_pools || []).filter(p => match(p.prefix, p.source, p.delegated_to))
        .sort((a, b) => comparePrefixes(a.prefix, b.prefix) || compareZones(a.source, b.source) || compareZones(a.delegated_to, b.delegated_to));
    const assignments = allAssignments(data).filter(a => match(a.prefix, a.source, a.assigned_to, a.tag))
        .sort((a, b) => comparePrefixes(a.prefix, b.prefix) || compareZones(a.assigned_to, b.assigned_to) || compareZones(a.source, b.source));
    const nonSharedAssignments = assignments.filter(a => !a.shared);
    const sharedAssignmentGroups = groupSharedAssignments(assignments);
    return `
        <h2>IPAM Pools</h2>
        ${tableWrap(`<table class="routes-table">
            <thead><tr><th>Prefix</th><th class="zone-column">Source</th><th class="zone-column">Delegated To</th></tr></thead>
            <tbody>${pools.map(pool => `
                <tr><td><code>${esc(pool.prefix || '-')}</code></td><td class="zone-column">${esc(pool.source || '-')}</td><td class="zone-column">${esc(pool.delegated_to || '-')}</td></tr>`).join('') || emptyRow(3)}</tbody>
        </table>`)}
        <h2>Non-shared IPAM Assignments</h2>
        ${tableWrap(`<table class="routes-table">
            <thead><tr><th>Prefix</th><th class="zone-column">Source</th><th class="zone-column">Assigned To</th><th>Tag</th></tr></thead>
            <tbody>${nonSharedAssignments.map(info => `
                <tr>
                    <td><code>${esc(info.prefix || '-')}</code></td>
                    <td class="zone-column">${esc(info.source || '-')}</td>
                    <td class="zone-column">${esc(info.assigned_to || '-')}</td>
                    <td>${esc(info.tag || '-')}</td>
                </tr>`).join('') || emptyRow(4)}</tbody>
        </table>`)}
        <h2>Shared IPAM Assignments ${stateBadge('shared')}</h2>
        ${tableWrap(`<table class="routes-table">
            <thead><tr><th>Prefix</th><th>Participating Nodes</th></tr></thead>
            <tbody>${sharedAssignmentGroups.map(group => `
                <tr><td><code>${esc(group.prefix || '-')}</code></td><td>${participantList(group.members)}</td></tr>`).join('') || emptyRow(2)}</tbody>
        </table>`)}`;
}
