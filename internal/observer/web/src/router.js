// router.js — hash routing with deep-linkable selection/filter state,
// plus UI-state preservation across re-renders (scroll position, active
// input, open <details> elements).

import * as store from './store.js';
import * as overview from './pages/overview.js';
import * as gossip from './pages/gossip.js';
import * as zones from './pages/zones.js';
import * as overlay from './pages/overlay.js';
import * as health from './pages/health.js';
import * as routes from './pages/routes.js';
import * as bird from './pages/bird.js';
import * as timeline from './pages/timeline.js';

const PAGES = { overview, gossip, zones, overlay, health, routes, bird, events: timeline };

let route = { page: 'overview', selected: '', filter: '' };

// Hash grammar: #/<page>[/<selection>][?f=<filter>]
export function parseHash() {
    const raw = window.location.hash.slice(1) || '/';
    const [pathPart, queryPart] = raw.split('?');
    const parts = pathPart.split('/').filter(Boolean);
    const page = PAGES[parts[0]] ? parts[0] : 'overview';
    const selected = parts[1] ? decodeURIComponent(parts.slice(1).join('/')) : '';
    const params = new URLSearchParams(queryPart || '');
    return { page, selected, filter: params.get('f') || '' };
}

export function navigate(page, selected, filter) {
    let hash = `#/${page}`;
    if (selected) hash += `/${encodeURIComponent(selected)}`;
    if (filter) hash += `?f=${encodeURIComponent(filter)}`;
    if (window.location.hash !== hash) {
        // Keep hash URLs without triggering native fragment scrolling.
        window.history.pushState(null, '', hash);
    }
    handleHashChange();
}

export function currentRoute() {
    return route;
}

export function handleHashChange() {
    route = parseHash();
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.toggle('active', link.dataset.page === route.page);
    });
    const mod = PAGES[route.page];
    store.setWatched(mod.deps || []);
    store.refreshWatched();
    renderCurrent();
}

// renderCurrent redraws the page body while preserving UI state.
export function renderCurrent() {
    const content = document.getElementById('content');
    if (!content) return;
    const state = captureUIState(content);
    PAGES[route.page].render(content, route);
    restoreUIState(content, state);
}

export function captureUIState(root) {
    const openDetails = [];
    root.querySelectorAll('details').forEach((d, i) => {
        if (d.open) openDetails.push(i);
    });
    let input = null;
    const active = document.activeElement;
    if (active && root.contains(active) && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')) {
        input = {
            selector: active.id ? `#${active.id}` : '',
            start: active.selectionStart,
            end: active.selectionEnd,
        };
    }
    return { scrollTop: root.scrollTop, openDetails, input };
}

export function restoreUIState(root, state) {
    if (!state) return;
    const details = root.querySelectorAll('details');
    state.openDetails.forEach(i => {
        if (details[i]) details[i].open = true;
    });
    if (state.input && state.input.selector) {
        const el = root.querySelector(state.input.selector);
        if (el) {
            el.focus();
            try { el.setSelectionRange(state.input.start, state.input.end); } catch { /* not supported */ }
        }
    }
    root.scrollTop = state.scrollTop;
}
