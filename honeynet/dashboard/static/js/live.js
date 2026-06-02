const POLL_INTERVAL = 10000;

const PATTERN_COLORS = {
    FULL_SPECTRUM:       "badge-FULL_SPECTRUM",
    SSH_THEN_PAYLOAD:    "badge-SSH_THEN_PAYLOAD",
    SSH_THEN_LATERAL:    "badge-SSH_THEN_LATERAL",
    PAYLOAD_AND_LATERAL: "badge-PAYLOAD_AND_LATERAL",
    BRUTE_FORCE_SSH:     "badge-BRUTE_FORCE_SSH",
    AUTOMATED_EXPLOIT:   "badge-AUTOMATED_EXPLOIT",
    RECON_ONLY:          "badge-RECON_ONLY",
    LOW_SSH_ACTIVITY:    "badge-LOW_SSH_ACTIVITY",
};

function setLiveIndicator(ok) {
    const el = document.getElementById("live-indicator");
    if (!el) return;
    if (ok) {
        el.className = "badge bg-success d-flex align-items-center gap-1";
        el.innerHTML = '<span class="live-dot"></span> Live';
    } else {
        el.className = "badge bg-danger d-flex align-items-center gap-1";
        el.innerHTML = '<span class="live-dot"></span> Offline';
    }
}

function updateStatCards(data) {
    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el && el.textContent != String(val)) {
            el.textContent = val;
            el.classList.add("stat-updated");
            setTimeout(() => el.classList.remove("stat-updated"), 600);
        }
    };
    set("stat-total",      data.total);
    set("stat-unique-ips", data.unique_ips);
    set("stat-patterns",   data.patterns.length);
    set("stat-enriched",   data.enriched_ips);
}

function formatTS(ts) {
    return ts ? ts.substring(0, 19) : "-";
}

function buildSessionRow(s, hasIntel, trAttr) {
    trAttr = trAttr || '';
    const proxyBadge   = (hasIntel && s.is_proxy)   ? '<span class="badge bg-warning text-dark ms-1">VPN</span>'   : '';
    const hostingBadge = (hasIntel && s.is_hosting) ? '<span class="badge bg-info text-dark ms-1">Cloud</span>' : '';

    let countryCell = '';
    if (hasIntel) {
        const flag = s.country_code
            ? `<img src="https://flagcdn.com/16x12/${s.country_code.toLowerCase()}.png" alt="${s.country_code}" class="me-1">`
            : '';
        countryCell = `<td>${flag}${s.country || '-'}</td><td>${s.isp || '-'}</td>`;
    }

    const patternClass = PATTERN_COLORS[s.pattern] || '';
    return `
        <tr${trAttr}>
            <td>${formatTS(s.timestamp)}</td>
            <td>
                <a href="/ip/${s.source_ip}" class="ip-link"><code>${s.source_ip}</code></a>
                ${proxyBadge}${hostingBadge}
            </td>
            ${countryCell}
            <td><span class="pattern-badge ${patternClass}">${s.pattern}</span></td>
            <td>${s.hits_cowrie}</td>
            <td>${s.hits_dionaea}</td>
            <td>${s.hits_opencanary}</td>
            <td>${formatTS(s.first_seen)}</td>
            <td>${formatTS(s.last_seen)}</td>
        </tr>`;
}

function updateSessionTable(data) {
    const tbody = document.querySelector("table.table-striped tbody");
    if (!tbody) return;

    // No sessions yet: show the placeholder instead of bailing out, so the
    // table reflects reality even before the first correlation arrives.
    if (!data.recent_sessions.length) {
        tbody.innerHTML =
            '<tr id="empty-sessions-row"><td colspan="11" class="text-muted text-center py-3">' +
            'No correlated sessions yet. Wait for the correlator to process some events.' +
            '</td></tr>';
        const btn0 = document.getElementById("btn-show-sessions");
        if (btn0) btn0.style.display = "none";
        return;
    }

    const MAX_VISIBLE = 10;
    const btn = document.getElementById("btn-show-sessions");
    // Check if rows are currently expanded (button says "Show Less")
    const isExpanded = btn && btn.textContent.trim() === "Show Less";

    tbody.innerHTML = data.recent_sessions
        .map((s, i) => {
            const hide = (i >= MAX_VISIBLE && !isExpanded) ? ' class="d-none session-row"' : (i >= MAX_VISIBLE ? ' class="session-row"' : '');
            return buildSessionRow(s, data.has_intel, hide);
        })
        .join("");

    // Update the show-more button count
    if (btn) {
        const hiddenCount = Math.max(0, data.recent_sessions.length - MAX_VISIBLE);
        if (hiddenCount > 0) {
            btn.style.display = "";
            if (!isExpanded) {
                btn.textContent = `Show More (${hiddenCount} hidden)`;
            }
        } else {
            btn.style.display = "none";
        }
    }
}

// Repaint the pattern doughnut (built in main.js) without rebuilding it.
function updatePatternChart(data) {
    const chart = window.__patternChart;
    if (!chart || !data.patterns) return;
    const labels = data.patterns.map(p => p.pattern);
    const counts = data.patterns.map(p => p.cnt);
    const colors = labels.map(l => (window.PATTERN_COLORS || {})[l] || "#bdc3c7");
    chart.data.labels = labels;
    chart.data.datasets[0].data = counts;
    chart.data.datasets[0].backgroundColor = colors;
    chart.update();
}

// Rebuild the "Pattern Breakdown" table. There are at most ~9 distinct pattern
// types, so we always show them all live — no Show More pagination needed.
function updateBreakdownTable(data) {
    const tbody = document.getElementById("breakdown-tbody");
    if (!tbody || !data.patterns) return;

    tbody.innerHTML = data.patterns.map(p => `<tr>
        <td><span class="pattern-badge badge-${p.pattern}">${p.pattern}</span></td>
        <td>${p.cnt}</td>
    </tr>`).join("");

    const btn = document.getElementById("btn-show-breakdown");
    if (btn) btn.style.display = "none";
}

// Rebuild the "Top ASN / ISP" table.
function updateAsnTable(data) {
    const tbody = document.getElementById("asn-tbody");
    if (!tbody || !data.top_asns) return;
    tbody.innerHTML = data.top_asns.map(a => `<tr>
        <td><code>${a.asn || '-'}</code></td>
        <td>${a.isp || '-'}</td>
        <td>${a.cnt}</td>
    </tr>`).join("");
}

// Repaint the country bar chart if it exists.
function updateCountryChart(data) {
    const chart = window.__countryChart;
    if (!chart || !data.top_countries) return;
    chart.data.labels = data.top_countries.map(c => c.country);
    chart.data.datasets[0].data = data.top_countries.map(c => c.cnt);
    chart.update();
}

// On an empty initial load the chart / breakdown sections aren't rendered at all
// (their {% if %} blocks were false). The moment the first data arrives we reload
// once so the full layout materialises; afterwards everything updates live above.
let _hadDataAtLoad = null;
function maybeReloadForNewSections(data) {
    if (_hadDataAtLoad === null) {
        _hadDataAtLoad = data.total > 0;
        return;
    }
    if (data.total > 0 && !window.__patternChart) {
        location.reload();
    }
}

async function poll() {
    try {
        const resp = await fetch("/api/stats");
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        setLiveIndicator(true);
        updateStatCards(data);
        updateSessionTable(data);
        updatePatternChart(data);
        updateBreakdownTable(data);
        updateAsnTable(data);
        updateCountryChart(data);
        maybeReloadForNewSections(data);
    } catch (err) {
        console.warn("[live] Poll failed:", err);
        setLiveIndicator(false);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    setInterval(poll, POLL_INTERVAL);
    setTimeout(poll, 2000);
});
