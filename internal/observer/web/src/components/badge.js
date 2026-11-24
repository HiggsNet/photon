// badge.js — semantic state badge and status dot.

import { esc } from '../format.js';

const TONE = {
    up: 'ok', healthy: 'ok', running: 'ok', established: 'ok', live: 'ok', active: 'ok',
    connecting: 'warn', degraded: 'warn', stale: 'warn', pending: 'warn', polling: 'warn',
    idle: 'warn', shared: 'warn',
    down: 'err', error: 'err', revoked: 'err', offline: 'err', failed: 'err',
    synced: 'ok', syncing: 'warn', backoff: 'warn', retry_pending: 'warn',
};

export function toneFor(state) {
    return TONE[String(state || '').toLowerCase()] || 'unknown';
}

export function badge(text, tone) {
    return `<span class="badge badge-${tone || 'unknown'}">${esc(text)}</span>`;
}

export function stateBadge(state) {
    return badge(state || 'unknown', toneFor(state));
}

export function dot(state) {
    return `<span class="dot dot-${toneFor(state)}" title="${esc(state || 'unknown')}"></span>`;
}
