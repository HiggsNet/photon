import { esc } from '../format.js';
import { navigate } from '../router.js';
import { emptyState, loading } from './card.js';

export function directoryGroups(items, groupOf, renderGroup) {
    const groups = new Map();
    for (const item of items) {
        const name = groupOf(item);
        if (!groups.has(name)) groups.set(name, []);
        groups.get(name).push(item);
    }
    return Array.from(groups, ([name, group]) => renderGroup(name, group)).join('');
}

export function directoryGroup(name, rows, secondary = '') {
    return `<section class="directory-group">
        <h3><span title="${esc(name)}">${esc(name)}</span>${secondary ? `<small title="${esc(secondary)}">${esc(secondary)}</small>` : ''}</h3>
        ${rows}
    </section>`;
}

export function linkDirectory(links, renderRow) {
    const hasMultipleGroups = links.some(link => link.group_id !== links[0].group_id);
    return directoryGroups(links, link => link.peer_zone || '-', (zone, items) => {
        const group = items[0].group_id;
        const mixed = items.some(item => item.group_id !== group);
        const rows = items.map(item => renderRow(item, mixed)).join('');
        return directoryGroup(zone, rows, hasMultipleGroups && !mixed ? group : '');
    });
}

export function directoryRow(key, label, selected, cells) {
    return `<button type="button" class="directory-row" data-directory-key="${esc(key)}"
        aria-pressed="${selected}" title="${esc(label)}">${cells}</button>`;
}

export function underlayLabel(link) {
    const path = link.path_key || link.desired?.path_key || '';
    const family = link.underlay_family || path.replace(/^family:/, '');
    if (family === 'ipv4') return 'IPv4';
    if (family === 'ipv6') return 'IPv6';
    return family && family !== 'default' ? family : link.interface_name || link.desired?.interface_name || 'Default';
}

const listPositions = new WeakMap();

export function renderInspectorLoading(container, page, header) {
    if (container.querySelector('.inspector')?.dataset.page !== page) {
        container.innerHTML = header + loading();
    }
}

export function renderInspector(container, route, {header, columns, list, empty, detail, selection, openDetail}) {
    const old = container.querySelector('.inspector');
    const samePage = old?.dataset.page === route.page;
    const sameList = samePage && old.dataset.filter === route.filter;
    const oldList = old?.querySelector('.directory-scroll');
    const oldDetail = old?.querySelector('.inspector-detail');
    const oldSelection = old?.dataset.selection;
    const listPosition = !sameList ? 0 : oldList.getClientRects().length
        ? oldList.scrollTop
        : listPositions.get(container) || 0;
    const detailPosition = samePage && oldSelection === selection ? oldDetail.scrollTop : 0;
    const active = document.activeElement;
    const focusedKey = samePage && container.contains(active) ? active.dataset.directoryKey : undefined;
    const returningToList = old?.querySelector('.inspector-back') === active;

    const directoryContent = list || emptyState(empty);
    const detailContent = `<button type="button" class="btn inspector-back">← Back to list</button>${detail}`;
    if (samePage) {
        container.querySelector('.page-header').outerHTML = header;
        old.classList.toggle('inspector-selected', openDetail);
        old.dataset.filter = route.filter;
        old.dataset.selection = selection;
        oldList.innerHTML = directoryContent;
        oldDetail.innerHTML = detailContent;
    } else {
        container.innerHTML = `${header}
        <div class="inspector inspector-${esc(route.page)}${openDetail ? ' inspector-selected' : ''}"
            data-page="${esc(route.page)}" data-filter="${esc(route.filter)}" data-selection="${esc(selection)}">
            <section class="directory" aria-label="${esc(columns[0])} list">
                <div class="directory-columns" aria-hidden="true">${columns.map(column => `<span>${esc(column)}</span>`).join('')}</div>
                <div class="directory-scroll" tabindex="0">${directoryContent}</div>
            </section>
            <section class="inspector-detail" aria-label="Details" tabindex="0">
                ${detailContent}
            </section>
        </div>`;
    }

    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
    const listPane = container.querySelector('.directory-scroll');
    const detailPane = container.querySelector('.inspector-detail');
    const back = detailPane.querySelector('.inspector-back');
    back.addEventListener('click', () => navigate(route.page, '', route.filter));
    const buttons = Array.from(container.querySelectorAll('[data-directory-key]'));
    buttons.forEach(button => {
        button.addEventListener('click', () => navigate(route.page, button.dataset.directoryKey, route.filter));
    });
    listPositions.set(container, listPosition);
    listPane.scrollTop = listPosition;
    detailPane.scrollTop = detailPosition;
    listPane.onscroll = () => {
        if (listPane.getClientRects().length) listPositions.set(container, listPane.scrollTop);
    };

    if (!sameList && route.selected && listPane.getClientRects().length) {
        listPane.querySelector('[aria-pressed="true"]')?.scrollIntoView({block: 'nearest'});
    }
    if (sameList && (focusedKey !== undefined || returningToList)) {
        if (!listPane.getClientRects().length) {
            back.focus({preventScroll: true});
        } else {
            const button = buttons.find(button => button.dataset.directoryKey === (focusedKey ?? oldSelection));
            (button || listPane).focus({preventScroll: true});
        }
    }
}
