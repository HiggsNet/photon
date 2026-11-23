// health_history.js — RTT history panel for the Health page: range
// selector (5m/30m/1h/6h/24h) with on-demand series loading.

import { fetchAPI } from '../api.js';
import { esc } from '../format.js';
import { healthChart } from '../components/chart.js';

const RANGES = ['5m', '30m', '1h', '6h', '24h'];
const RANGE_STEPS = { '5m': '10s', '30m': '1m', '1h': '2m', '6h': '10m', '24h': '30m' };

const METRICS = { rtt: 'Small RTT', loss: 'Small loss', large_rtt: 'Large RTT', large_loss: 'Large loss' };
const selections = new Map(); // preserve range/metric across SSE-driven renders

export function historyPanel(instanceID, largeEnabled = false) {
    if (!instanceID) return '<div class="muted">No link instance selected.</div>';
    const selection = selections.get(instanceID) || {range: '30m', metric: 'rtt'};
    const metric = largeEnabled || !selection.metric.startsWith('large_') ? selection.metric : 'rtt';
    const buttons = RANGES.map(r =>
        `<button type="button" class="btn range-btn${r === selection.range ? ' active' : ''}" data-health-range="${r}">${r}</button>`).join('');
    return `<div class="history-panel" data-link-id="${esc(instanceID)}">
        <div class="history-toolbar" role="group" aria-label="Probe history range">${buttons}
            <select data-health-metric aria-label="Probe history metric">${Object.entries(METRICS)
                .filter(([key]) => largeEnabled || !key.startsWith('large_'))
                .map(([key, label]) => `<option value="${key}"${key === metric ? ' selected' : ''}>${label}</option>`).join('')}</select>
        </div>
        <div class="health-chart-body muted">Loading probe history…</div>
    </div>`;
}

async function loadHistory(panel, range) {
    const body = panel.querySelector('.health-chart-body');
    if (!body) return;
    const linkID = panel.dataset.linkId || '';
    const step = RANGE_STEPS[range] || '1m';
    const metric = panel.querySelector('[data-health-metric]')?.value || 'rtt';
    selections.set(linkID, {range, metric});
    const key = `${linkID}:${range}:${metric}`;
    if (body.dataset.loadingKey === key || (!body.dataset.loadingKey && body.dataset.loadedKey === key)) return;
    body.dataset.loadingKey = key;
    body.classList.add('muted');
    body.textContent = 'Loading probe history…';
    try {
        const data = await fetchAPI(`/health/${encodeURIComponent(linkID)}/series?metric=${metric}&range=${range}&step=${step}`);
        if (body.dataset.loadingKey !== key) return;
        const series = data.series || {};
        body.classList.remove('muted');
        body.innerHTML = healthChart(series, series.range || range, series.step || step);
        body.dataset.loadedKey = key;
    } catch (e) {
        body.classList.add('muted');
        if (body.dataset.loadingKey !== key) return;
        body.textContent = `Probe history unavailable: ${e.message}`;
    } finally {
        if (body.dataset.loadingKey === key) delete body.dataset.loadingKey;
    }
}

export function bindHistory(root, datasource) {
    if (!datasource || !datasource.configured) return;
    const loadActive = panel => {
        const active = panel.querySelector('[data-health-range].active');
        loadHistory(panel, active ? active.dataset.healthRange : '30m');
    };
    root.querySelectorAll('.history-panel').forEach(loadActive);
    root.querySelectorAll('[data-health-metric]').forEach(select => {
        select.addEventListener('change', () => loadActive(select.closest('.history-panel')));
    });
    root.querySelectorAll('[data-health-range]').forEach(button => {
        button.addEventListener('click', () => {
            const panel = button.closest('.history-panel');
            if (!panel) return;
            panel.querySelectorAll('[data-health-range]').forEach(b => b.classList.toggle('active', b === button));
            loadHistory(panel, button.dataset.healthRange);
        });
    });
}
