// chart.js — SVG sparkline and RTT history chart (pure HTML/SVG strings).

import { esc, ms } from '../format.js';

export function sparkline(values) {
    if (!values || values.length === 0) return '<span class="muted">-</span>';
    const width = 96;
    const height = 24;
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = Math.max(1, max - min);
    const points = values.map((v, i) => {
        const x = values.length === 1 ? width : (i / (values.length - 1)) * width;
        const y = height - ((v - min) / span) * (height - 4) - 2;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    return `<svg class="sparkline" viewBox="0 0 ${width} ${height}" role="img"><polyline points="${points}"></polyline></svg>`;
}

export function healthChartLines(series) {
    const rawLines = (series && Array.isArray(series.lines) && series.lines.length > 0)
        ? series.lines
        : [{ probe_role: 'active', points: (series && series.points) || [] }];
    return rawLines.map(line => {
        const points = (line.points || [])
            .map(p => ({ ts: Number(p.unix_ms), value: Number(p.value) }))
            .filter(p => Number.isFinite(p.ts) && Number.isFinite(p.value));
        return { label: line.probe_role || line.probe_id || 'active', points };
    }).filter(line => line.points.length > 0);
}

export function healthChart(series, range, step) {
    const percent = series && series.unit === 'percent';
    const formatValue = value => percent ? `${Number(value).toFixed(1)}%` : (Number(value) === 0 ? '0ms' : ms(value));
    const label = percent ? 'Loss' : 'RTT';
    const lines = healthChartLines(series);
    const all = lines.flatMap(line => line.points);
    if (all.length === 0) {
        return `<div class="empty-state compact">No ${label} samples for ${esc(range)}.</div>`;
    }
    const width = 720;
    const height = 220;
    const pad = { top: 18, right: 20, bottom: 34, left: 54 };
    const xs = all.map(p => p.ts);
    const ys = all.map(p => p.value);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(0, ...ys);
    const maxY = Math.max(...ys);
    const xSpan = Math.max(1, maxX - minX);
    const ySpan = Math.max(1, maxY - minY);
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;
    const x = ts => pad.left + ((ts - minX) / xSpan) * plotW;
    const y = value => pad.top + plotH - ((value - minY) / ySpan) * plotH;
    const pathFor = points => points
        .map((p, i) => `${i === 0 ? 'M' : 'L'} ${x(p.ts).toFixed(1)} ${y(p.value).toFixed(1)}`)
        .join(' ');
    const latest = all.reduce((best, p) => (!best || p.ts > best.ts ? p : best), null);
    const avg = ys.reduce((sum, v) => sum + v, 0) / ys.length;
    const yTicks = [minY, minY + ySpan / 2, maxY];
    const start = new Date(minX).toLocaleTimeString();
    const end = new Date(maxX).toLocaleTimeString();
    return `
        <div class="chart-meta">
            <span>Latest ${formatValue(latest.value)}</span>
            <span>Avg ${formatValue(avg)}</span>
            <span>Max ${formatValue(maxY)}</span>
            <span>${esc(range)} · ${esc(step)}</span>
        </div>
        <div class="chart-legend">
            ${lines.map((line, i) => `<span><i class="legend-swatch line-${i % 4}"></i>${esc(line.label)}</span>`).join('')}
        </div>
        <svg class="history-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="${label} history chart">
            ${yTicks.map(tick => `
                <line class="chart-grid" x1="${pad.left}" y1="${y(tick).toFixed(1)}" x2="${width - pad.right}" y2="${y(tick).toFixed(1)}"></line>
                <text class="chart-label" x="${pad.left - 8}" y="${(y(tick) + 4).toFixed(1)}" text-anchor="end">${esc(formatValue(tick))}</text>`).join('')}
            <line class="chart-axis" x1="${pad.left}" y1="${height - pad.bottom}" x2="${width - pad.right}" y2="${height - pad.bottom}"></line>
            <line class="chart-axis" x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${height - pad.bottom}"></line>
            ${lines.map((line, i) => `
                <path class="history-line line-${i % 4}" d="${pathFor(line.points)}"></path>
                ${line.points.map(p => `<circle class="history-point line-${i % 4}" cx="${x(p.ts).toFixed(1)}" cy="${y(p.value).toFixed(1)}" r="2.6"></circle>`).join('')}
            `).join('')}
            <text class="chart-label" x="${pad.left}" y="${height - 10}" text-anchor="start">${esc(start)}</text>
            <text class="chart-label" x="${width - pad.right}" y="${height - 10}" text-anchor="end">${esc(end)}</text>
        </svg>`;
}
