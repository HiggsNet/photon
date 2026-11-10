// events.js — SSE connection, event → endpoint invalidation mapping,
// item-level invalidation for payload-carrying events, and fallback
// polling of the current page's watched keys only.

import { API_BASE } from './api.js';
import * as store from './store.js';

// Event type → endpoints invalidated by that event.
const INVALIDATE = {
    state_changed: ['/status', '/zones', '/peers', '/links', '/health'],
    peer_updated: ['/peers', '/status'],
    link_updated: ['/links', '/status'],
    health_updated: ['/health'],
    route_changed: ['/routes'],
    bird_updated: ['/bird', '/status'],
};

// The replay-buffer timeline key is refetched on every event (when watched).
const RECENT_KEY = '/events/recent';

const POLL_INTERVAL_MS = 5000;
const RECONNECT_MS = 10000;

let eventSource = null;
let pollTimer = null;
let mode = 'disconnected';

// Item-level invalidation handlers: pages holding per-item caches (peer
// detail, health sparklines) register fn(eventType, payload) here.
const itemHandlers = new Set();

export function onItemInvalidate(fn) {
    itemHandlers.add(fn);
    return () => itemHandlers.delete(fn);
}

function handleEvent(type, raw) {
    let payload = null;
    if (raw) {
        try {
            payload = (JSON.parse(raw) || {}).payload ?? null;
        } catch {
            payload = null;
        }
    }
    for (const fn of itemHandlers) {
        try {
            fn(type, payload);
        } catch { /* one bad handler must not break invalidation */ }
    }
    store.invalidate([...(INVALIDATE[type] || []), RECENT_KEY]);
}

export function connect() {
    close();
    try {
        eventSource = new EventSource(`${API_BASE}/events`);
        eventSource.addEventListener('connected', () => setMode('live'));
        for (const type of Object.keys(INVALIDATE)) {
            eventSource.addEventListener(type, ev => handleEvent(type, ev.data));
        }
        eventSource.onerror = () => {
            close();
            setMode('polling');
            setTimeout(() => {
                if (mode === 'polling') connect();
            }, RECONNECT_MS);
        };
    } catch {
        setMode('polling');
    }
}

export function connectionMode() {
    return mode;
}

function close() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
}

function setMode(next) {
    mode = next;
    renderStatus();
    if (next === 'live' || next === 'polling') {
        startPolling();
    }
}

function renderStatus() {
    const el = document.getElementById('connection-status');
    if (!el) return;
    const states = {
        live: { label: 'Live', tone: 'ok' },
        polling: { label: 'Polling', tone: 'warn' },
        disconnected: { label: 'Disconnected', tone: 'err' },
    };
    const state = states[mode] || states.disconnected;
    el.className = `conn conn-${mode}`;
    el.innerHTML = `<span class="dot dot-${state.tone}"></span><span class="conn-label">${state.label}</span>`;
}

function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(() => {
        if (mode === 'polling') {
            store.refreshWatched();
        } else if (mode === 'live' && store.watched().includes('/peers')) {
            // Session and retry state can change without a verified commit.
            store.fetch('/peers');
        }
    }, POLL_INTERVAL_MS);
}
