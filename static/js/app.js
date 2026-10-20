/* ── NIRVANA LAN — app.js ──
   Todo lo que llega de la red (nombres DNS, banners, recursos SMB, registros
   DNS, notas) se escapa con esc() antes de pintarlo: un equipo hostil de la
   red escaneada no puede inyectar HTML ni scripts en el panel. */
'use strict';

const state = {
  view: 'dashboard', hosts: [], vulns: [], sevFilter: 'ALL', networks: [],
  lang: document.documentElement.lang === 'en' ? 'en' : 'es',
};
const RISKY_PORTS = [21, 23, 135, 137, 139, 445, 1433, 3306, 3389, 5900, 6379, 9200, 11211, 27017];

// ─── UTILIDADES ───
const $ = id => document.getElementById(id);

function esc(v) {
  return String(v === null || v === undefined ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function t(key, params) {
  const dict = (window.I18N && window.I18N[state.lang]) || {};
  let s = dict[key] !== undefined ? dict[key] : (window.I18N.es[key] !== undefined ? window.I18N.es[key] : key);
  if (params) for (const k in params) s = s.split('{' + k + '}').join(String(params[k]));
  return s;
}

/** Mensaje del backend: {msg, params} o texto plano. */
function tmsg(status, fallback) {
  if (status && status.msg) return t(status.msg, status.params || {});
  if (status && status.error) return t(status.error, status.params || {});
  return (status && status.message) || fallback || '';
}

function sevLabel(sev) { return t('sev_' + sev); }

function vulnText(v) {
  if (state.lang !== 'es' || !window.VULN_ES[v.vuln_type]) return [v.description, v.recommendation];
  const es = window.VULN_ES[v.vuln_type];
  const detail = (String(v.description || '').match(/(Banner: .*|\(sysDescr: .*\))\.?$/) || [])[1];
  return [es[0] + (detail ? ' ' + detail : ''), es[1]];
}

function riskColor(r) { return r >= 70 ? '#ef4444' : r >= 40 ? '#f97316' : r >= 20 ? '#eab308' : '#10b981'; }

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d) ? esc(iso) : d.toLocaleString(state.lang === 'es' ? 'es-ES' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' });
}

/** Llamada a la API. Rutas relativas (funciona en Flask y en la demo de Pages). */
async function api(path, opts = {}) {
  const init = { method: opts.method || 'GET', headers: {} };
  if (init.method !== 'GET') init.headers['X-Nirvana'] = '1';
  if (opts.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  const res = await fetch('api/' + path, init);
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok) {
    const err = new Error(data && data.error ? tmsg(data) : 'HTTP ' + res.status);
    err.data = data;
    throw err;
  }
  return data;
}

function notify(msg, type) {
  const el = $('notification');
  el.textContent = msg;
  el.className = 'notification show' + (type === 'error' ? ' error' : '');
  clearTimeout(el._timeout);
  el._timeout = setTimeout(() => el.classList.remove('show'), 4500);
}

function flashScanComplete() {
  const div = document.createElement('div');
  div.className = 'scan-complete-flash';
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 900);
}

const emptyState = key => '<div class="empty-state">' + esc(t(key)) + '</div>';
const emptyRow = (cols, key, params) => '<tr><td colspan="' + cols + '" class="empty-row">' + esc(t(key, params)) + '</td></tr>';

// ─── IDIOMA Y TEMA ───
function applyI18n() {
  document.documentElement.lang = state.lang;
  document.title = state.lang === 'es' ? 'Nirvana LAN — Auditoría de red local' : 'Nirvana LAN — Local network audit';
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-title]').forEach(el => { el.title = t(el.dataset.i18nTitle); el.setAttribute('aria-label', el.title); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { el.placeholder = t(el.dataset.i18nPlaceholder); });
  $('langToggle').textContent = state.lang === 'es' ? 'EN' : 'ES';
  setViewLabel();
}

function setLang(lang) {
  state.lang = lang;
  try { localStorage.setItem('nirvana-lang', lang); } catch (e) { /* sin almacenamiento */ }
  applyI18n();
  refreshCurrentView();
  renderNetworkHint();
}

function initTheme() { updateThemeIcon(document.documentElement.getAttribute('data-theme') || 'dark'); }
function toggleTheme() {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('nirvana-theme', next); } catch (e) { /* sin almacenamiento */ }
  updateThemeIcon(next);
}
function updateThemeIcon(theme) { $('themeIcon').textContent = theme === 'dark' ? '☀' : '☾'; }

function initClock() {
  const tick = () => { $('clock').textContent = new Date().toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
  tick();
  setInterval(tick, 1000);
}

// ─── NAVEGACIÓN ───
const VIEW_LABEL = {
  dashboard: 'nav_dashboard', discovery: 'disc_title', ports: 'ports_title', enumerate: 'enum_title',
  vulns: 'vuln_title', hosts: 'hosts_title', scheduler: 'sched_title', reports: 'rep_title',
};
function setViewLabel() { $('currentViewLabel').textContent = t(VIEW_LABEL[state.view] || 'nav_dashboard'); }

function switchView(name) {
  if (!VIEW_LABEL[name]) name = 'dashboard';
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.toggle('active', l.dataset.view === name));
  state.view = name;
  setViewLabel();
  if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
  refreshCurrentView();
  $('sidebar').classList.remove('open');
}

function refreshCurrentView() {
  const v = state.view;
  if (v === 'dashboard') loadDashboard();
  if (v === 'discovery') loadDiscoveryHosts();
  if (v === 'ports') { loadQuickButtons(); renderPortsTable(state.lastPorts); }
  if (v === 'hosts') loadHostsGrid();
  if (v === 'vulns') loadVulns();
  if (v === 'reports') loadReportSummary();
  if (v === 'scheduler') loadScheduledTasks();
}

// ─── RED LOCAL ───
async function loadNetworkInfo() {
  try {
    const data = await api('network-info');
    state.networks = data.networks || [];
    state.suggested = data.suggested;
    if (data.suggested && !$('discTarget').value) $('discTarget').value = data.suggested;
    renderNetworkHint();
  } catch (e) {
    $('networkHint').textContent = t('no_iface');
    $('networkInfo').textContent = t('not_detected');
  }
}

function renderNetworkHint() {
  const nets = state.networks || [];
  const hint = $('networkHint');
  if (!nets.length) {
    hint.textContent = t('no_iface');
    $('networkInfo').textContent = t('not_detected');
    return;
  }
  $('networkInfo').textContent = $('discTarget').value || nets[0].network;
  if (nets.length === 1) {
    const n = nets[0];
    hint.textContent = t('detected', { iface: n.interface, ip: n.ip, net: n.network });
    return;
  }
  hint.innerHTML = esc(t('select_iface')) + ' ' + nets.map(n =>
    '<button type="button" class="iface-chip' + ($('discTarget').value === n.network ? ' active' : '') +
    '" data-action="iface" data-net="' + esc(n.network) + '">' + esc(n.interface) + ' ' + esc(n.network) + '</button>').join(' ');
}

// ─── PANEL ───
async function loadDashboard() {
  try {
    const [stats, hosts] = await Promise.all([api('stats'), api('hosts')]);
    state.hosts = hosts;
    $('stat-hosts').textContent = stats.total_hosts;
    $('stat-critical').textContent = stats.critical;
    $('stat-high').textContent = stats.high;
    $('stat-medium').textContent = stats.medium;
    $('stat-vulns').textContent = stats.total_vulns;
    $('stat-scans').textContent = stats.scans;
    renderTopPortsChart(stats.top_ports);
    renderRiskChart(stats);
    renderRecentHosts(hosts.slice().sort((a, b) => (b.last_seen || '').localeCompare(a.last_seen || '')).slice(0, 8));
  } catch (e) { console.error(e); }
}

function renderTopPortsChart(ports) {
  const el = $('topPortsChart');
  if (!ports || !ports.length) { el.innerHTML = emptyState('no_port_data'); return; }
  const max = ports[0].count || 1;
  el.innerHTML = '<div class="bar-chart">' + ports.map(p =>
    '<div class="bar-row"><span class="bar-label">' + esc(p.port) + '/' + esc(p.service) + '</span>' +
    '<div class="bar-track"><div class="bar-fill" style="width:' + Math.max(8, Math.round(p.count / max * 100)) + '%">' + esc(p.count) + '</div></div></div>'
  ).join('') + '</div>';
}

function renderRiskChart(stats) {
  const el = $('riskChart');
  const total = stats.total_vulns || 0;
  if (!total) { el.innerHTML = emptyState('no_vuln_data'); return; }
  const items = [
    ['CRITICAL', stats.critical, '#ef4444'], ['HIGH', stats.high, '#f97316'],
    ['MEDIUM', stats.medium, '#eab308'], ['LOW', stats.low, '#3b82f6'],
  ].filter(i => i[1] > 0);
  el.innerHTML = '<div class="bar-chart">' + items.map(([sev, n, color]) =>
    '<div class="bar-row"><span class="bar-label" style="color:' + color + '">' + esc(sevLabel(sev)) + '</span>' +
    '<div class="bar-track"><div class="bar-fill" style="width:' + Math.max(8, Math.round(n / total * 100)) + '%;background:' + color + '">' + esc(n) + '</div></div></div>'
  ).join('') + '</div>';
}

const hostName = h => (h.hostname && h.hostname !== h.ip ? h.hostname : '—');
const ipLink = ip => '<button type="button" class="ip-link" data-action="host" data-ip="' + esc(ip) + '">' + esc(ip) + '</button>';

function renderRecentHosts(hosts) {
  const el = $('recentHostsTable');
  if (!hosts.length) { el.innerHTML = emptyState('no_hosts'); return; }
  el.innerHTML = '<div class="table-wrap"><table class="data-table"><thead><tr><th>' + esc(t('col_ip')) + '</th><th>' + esc(t('col_hostname')) +
    '</th><th>' + esc(t('col_os')) + '</th><th>' + esc(t('col_risk')) + '</th><th>' + esc(t('col_ports')) + '</th></tr></thead><tbody>' +
    hosts.map(h => {
      const risk = h.risk_score || 0;
      const ports = Object.keys(h.open_ports || {}).slice(0, 6).map(p => '<span class="port-chip">' + esc(p) + '</span>').join(' ');
      return '<tr><td>' + ipLink(h.ip) + '</td><td>' + esc(hostName(h)) + '</td><td>' + esc(h.os_guess || '—') +
        '</td><td style="color:' + riskColor(risk) + ';font-weight:700">' + esc(risk) + '</td><td>' + ports + '</td></tr>';
    }).join('') + '</tbody></table></div>';
}

// ─── SEGUIMIENTO DE ESCANEOS ───
function progressHtml(status, done) {
  const pct = done ? 100 : (status.progress || 0);
  const color = done ? ' style="color:var(--green)"' : '';
  return '<div class="progress-msg"' + color + '>' + (done ? '✓ ' : '') + esc(tmsg(status, t('p_running'))) + '</div>' +
    '<div class="progress-bar-wrap"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
    '<div class="progress-pct"' + color + '>' + pct + '%</div>';
}

function hostStream(hosts) {
  if (!hosts || !hosts.length) return '';
  return '<div class="found-hosts-stream">' + hosts.slice(-15).map(h =>
    '<div class="host-found-entry">▶ ' + esc(h.ip) + (h.hostname && h.hostname !== h.ip ? ' — ' + esc(h.hostname) : '') +
    (h.vendor && h.vendor !== 'Unknown' ? ' [' + esc(h.vendor) + ']' : '') + '</div>').join('') + '</div>';
}

/** Consulta el estado cada segundo. Devuelve una promesa con el estado final. */
function pollScan(scanId, progressId, onUpdate) {
  const progEl = $(progressId);
  return new Promise(resolve => {
    let errors = 0;
    const timer = setInterval(async () => {
      let status;
      try {
        status = await api('scan/status/' + scanId);
        errors = 0;
      } catch (e) {
        if (++errors < 4) return;
        clearInterval(timer);
        if (progEl) progEl.innerHTML = '<div class="scan-error">' + esc(t('connection_error')) + '</div>';
        resolve({ status: 'error' });
        return;
      }
      const finished = status.status === 'done' || status.status === 'error' || status.status === 'not_found';
      if (!finished) {
        if (progEl) progEl.innerHTML = progressHtml(status, false) + (onUpdate ? onUpdate(status) || '' : '');
        return;
      }
      clearInterval(timer);
      if (status.status !== 'done') {
        const m = tmsg(status, t('err_generic', { error: status.status }));
        if (progEl) progEl.innerHTML = '<div class="scan-error">⚠ ' + esc(m) + '</div>';
        notify(m, 'error');
      } else if (progEl) {
        progEl.innerHTML = progressHtml(status, true) + (onUpdate ? onUpdate(status) || '' : '');
      }
      resolve(status);
    }, 1000);
  });
}

async function startScan(body, progressId) {
  try {
    const data = await api('scan/start', { method: 'POST', body });
    return data.scan_id;
  } catch (e) {
    notify(e.message, 'error');
    if (progressId) $(progressId).innerHTML = '<div class="scan-error">⚠ ' + esc(e.message) + '</div>';
    return null;
  }
}

// ─── DESCUBRIMIENTO ───
async function startDiscovery(target) {
  target = (target || $('discTarget').value).trim();
  if (!target) return notify(t('enter_range'), 'error');
  if (!target.includes('/')) return notify(t('need_cidr'), 'error');
  const btn = $('startDiscovery');
  btn.disabled = true;
  btn.textContent = t('scanning');
  const id = await startScan({
    type: 'discovery', target,
    options: { os_detect: $('osDetect').checked, resolve_hostnames: $('resolveHostnames').checked, vendor_lookup: $('vendorLookup').checked },
  }, 'discProgress');
  if (id) {
    const status = await pollScan(id, 'discProgress', s => hostStream(s.hosts));
    if (status.status === 'done') {
      flashScanComplete();
      notify(t('discovery_done', { n: (status.hosts || []).length }));
    }
    loadDiscoveryHosts();
    loadDashboard();
  }
  btn.disabled = false;
  btn.textContent = t('start_discovery');
}

async function loadDiscoveryHosts() {
  try {
    const hosts = await api('hosts');
    state.hosts = hosts;
    $('discHostCount').textContent = hosts.length;
    const tbody = $('discHostsBody');
    if (!hosts.length) { tbody.innerHTML = emptyRow(7, 'no_hosts'); return; }
    tbody.innerHTML = hosts.map(h =>
      '<tr><td>' + ipLink(h.ip) + '</td><td>' + esc(hostName(h)) + '</td><td class="mono">' + esc(h.mac || '—') +
      '</td><td>' + esc(h.vendor || '—') + '</td><td>' + esc(h.os_guess || '—') + '</td>' +
      '<td><span style="color:' + (h.status === 'up' ? 'var(--green)' : 'var(--red)') + '">' + esc(h.status || 'up') + '</span></td>' +
      '<td class="actions">' +
      '<button class="btn-secondary btn-sm" data-action="to-ports" data-ip="' + esc(h.ip) + '">' + esc(t('btn_ports')) + '</button> ' +
      '<button class="btn-secondary btn-sm" data-action="to-vulns" data-ip="' + esc(h.ip) + '">' + esc(t('btn_vulns')) + '</button> ' +
      '<button class="btn-secondary btn-sm" data-action="host" data-ip="' + esc(h.ip) + '">' + esc(t('btn_details')) + '</button>' +
      '</td></tr>').join('');
  } catch (e) { console.error(e); }
}

async function clearHosts() {
  if (!confirm(t('confirm_clear'))) return;
  try {
    await api('hosts/clear', { method: 'POST' });
    notify(t('cleared'));
  } catch (e) { notify(e.message, 'error'); }
  loadDiscoveryHosts();
  loadDashboard();
}

// ─── PUERTOS ───
async function startPortScan() {
  const target = $('portTarget').value.trim();
  if (!target) return notify(t('enter_ip'), 'error');
  let range = $('portRange').value;
  if (range === 'custom') range = $('customPorts').value.trim();
  if (!range) return notify(t('enter_ports'), 'error');
  state.portTarget = target;
  $('portResultTitle').textContent = t('port_results_for', { ip: target });
  $('portCount').textContent = '0';
  $('portResultsBody').innerHTML = emptyRow(5, 'scanning_rows');
  const id = await startScan({ type: 'ports', target, port_range: range }, 'portProgress');
  if (!id) { renderPortsTable(null); return; }
  const status = await pollScan(id, 'portProgress', s => { renderPortsTable(s.ports, true); return ''; });
  if (status.status === 'done') {
    flashScanComplete();
    notify(t('ports_done', { n: (status.ports || []).length }));
    renderPortsTable(status.ports);
  }
}

function renderPortsTable(ports, live) {
  state.lastPorts = ports;
  const tbody = $('portResultsBody');
  if (!ports) { tbody.innerHTML = emptyRow(5, 'run_port_scan'); return; }
  $('portCount').textContent = ports.length;
  if (!ports.length) { tbody.innerHTML = emptyRow(5, live ? 'scanning_rows' : 'no_open_ports'); return; }
  tbody.innerHTML = ports.slice().sort((a, b) => a.port - b.port).map(p => {
    const risky = RISKY_PORTS.includes(p.port);
    return '<tr' + (risky ? ' class="row-risky"' : '') + '><td class="mono" style="font-weight:700;color:var(--accent)">' + esc(p.port) +
      '</td><td>' + esc(p.service) + '</td><td style="color:var(--green)">' + esc(t('open')) + '</td>' +
      '<td class="banner-cell" title="' + esc(p.banner || '') + '">' + esc(p.banner || '—') + '</td>' +
      '<td><span class="badge badge-' + (risky ? 'HIGH' : 'INFO') + '">' + esc(t(risky ? 'high_risk' : 'normal')) + '</span></td></tr>';
  }).join('');
}

async function loadQuickButtons() {
  const el = $('quickHostButtons');
  try {
    const hosts = await api('hosts');
    if (!hosts.length) { el.innerHTML = '<span class="muted">' + esc(t('no_hosts_quick')) + '</span>'; return; }
    el.innerHTML = hosts.map(h => '<button class="host-btn" data-action="to-ports" data-ip="' + esc(h.ip) + '">' + esc(h.ip) + '</button>').join('');
  } catch (e) { /* sin servidor */ }
}

function setPortTarget(ip) { $('portTarget').value = ip; closeModal(); switchView('ports'); }
function setVulnTarget(ip) { $('vulnTarget').value = ip; closeModal(); switchView('vulns'); }

// ─── DNS ───
async function startDNS() {
  const target = $('dnsTarget').value.trim();
  if (!target) return notify(t('enter_domain'), 'error');
  const id = await startScan({ type: 'dns', target }, 'dnsProgress');
  if (!id) return;
  const status = await pollScan(id, 'dnsProgress');
  if (status.status !== 'done') return;
  const results = status.results || {};
  $('dnsResultsCard').hidden = false;
  const types = Object.keys(results);
  $('dnsResults').innerHTML = !types.length ? emptyState('no_dns') : types.map(type =>
    '<div class="dns-record"><div class="dns-type">' + esc(type) + (type === 'AXFR' ? '<br><span class="axfr-warn">' + esc(t('axfr_open')) + '</span>' : '') +
    '</div><div class="dns-values">' + [].concat(results[type]).map(v => '<div class="dns-val">' + esc(v) + '</div>').join('') + '</div></div>'
  ).join('');
  notify(t('dns_done'));
}

// ─── SMB ───
async function startSMB() {
  const target = $('smbTarget').value.trim();
  if (!target) return notify(t('enter_ip'), 'error');
  const id = await startScan({ type: 'smb', target }, 'smbProgress');
  if (!id) return;
  const status = await pollScan(id, 'smbProgress');
  if (status.status !== 'done') return;
  const r = status.results || {};
  $('smbResultsCard').hidden = false;
  const block = (title, rows) => '<div class="dns-record"><div class="dns-type">' + esc(title) + '</div><div class="dns-values">' + rows + '</div></div>';
  let html = '';
  if (!r.port_open) {
    html = emptyState('smb_closed');
  } else {
    html += block(t('shares'), (r.shares || []).length
      ? r.shares.map(s => '<div class="dns-val">📁 ' + esc(s.name) + ' (' + esc(s.type) + ')</div>').join('')
      : '<div class="dns-val">' + esc(t('no_shares')) + '</div>');
    if ((r.users || []).length) html += block(t('users'), r.users.map(u => '<div class="dns-val">👤 ' + esc(u) + '</div>').join(''));
    html += block(t('smb_tool'), '<div class="dns-val">' + esc(r.tool || t('smb_no_tool')) + '</div>');
  }
  $('smbResults').innerHTML = html;
  notify(t('smb_done'));
}

// ─── VULNERABILIDADES ───
async function startVulnScan() {
  const target = $('vulnTarget').value.trim();
  if (!target) return notify(t('enter_ip'), 'error');
  const id = await startScan({ type: 'vulns', target }, 'vulnProgress');
  if (!id) return;
  const status = await pollScan(id, 'vulnProgress');
  if (status.status === 'done') {
    flashScanComplete();
    notify(t('vuln_done', { n: (status.vulns || []).length, score: status.risk_score || 0 }));
  }
  loadVulns();
}

async function scanAllHosts() {
  let hosts;
  try { hosts = await api('hosts'); } catch (e) { return notify(e.message, 'error'); }
  if (!hosts.length) return notify(t('scan_all_none'), 'error');
  notify(t('scan_all_queued', { n: hosts.length }));
  const queue = hosts.map(h => h.ip);
  let done = 0;
  const worker = async () => {
    while (queue.length) {
      const ip = queue.shift();
      const id = await startScan({ type: 'vulns', target: ip });
      if (id) await pollScan(id, null);
      done++;
      $('vulnProgress').innerHTML = progressHtml({ msg: 'scan_all_queued', params: { n: hosts.length },
        progress: Math.round(done / hosts.length * 100) }, false) + '<div class="progress-msg">' + esc(done + '/' + hosts.length) + '</div>';
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
  notify(t('scan_all_done', { n: hosts.length }));
  loadVulns();
}

async function loadVulns() {
  try { state.vulns = await api('vulnerabilities'); } catch (e) { state.vulns = []; }
  renderVulnsTable();
}

function renderVulnsTable() {
  const tbody = $('vulnsBody');
  const vulns = state.sevFilter === 'ALL' ? state.vulns : state.vulns.filter(v => v.severity === state.sevFilter);
  if (!vulns.length) {
    tbody.innerHTML = state.sevFilter === 'ALL' ? emptyRow(7, 'no_vulns') : emptyRow(7, 'no_vulns_sev', { sev: sevLabel(state.sevFilter) });
    return;
  }
  tbody.innerHTML = vulns.map(v => {
    const [desc, fix] = vulnText(v);
    return '<tr><td>' + ipLink(v.host_ip) + '</td><td class="mono">' + esc(v.port) + '</td><td>' + esc(v.service) +
      '</td><td class="mono" style="font-weight:700">' + esc(v.vuln_type) + '</td>' +
      '<td><span class="badge badge-' + esc(v.severity) + '">' + esc(sevLabel(v.severity)) + '</span></td>' +
      '<td class="desc-cell">' + esc(desc) + '</td><td class="fix-cell">' + esc(fix) + '</td></tr>';
  }).join('');
}

// ─── INVENTARIO ───
async function loadHostsGrid() {
  try { state.hosts = await api('hosts'); } catch (e) { state.hosts = []; }
  filterHosts();
}

function renderHostsGrid(hosts) {
  const el = $('hostsGrid');
  if (!hosts.length) { el.innerHTML = emptyState('no_hosts'); return; }
  el.innerHTML = hosts.map(h => {
    const risk = h.risk_score || 0;
    const ports = Object.entries(h.open_ports || {});
    const chips = ports.slice(0, 8).map(([p, s]) => {
      const svc = s && typeof s === 'object' ? s.service : s;
      return '<span class="port-chip' + (RISKY_PORTS.includes(parseInt(p, 10)) ? ' risky' : '') + '">' + esc(p) + '/' + esc(svc) + '</span>';
    }).join('') + (ports.length > 8 ? '<span class="port-chip">+' + (ports.length - 8) + '</span>' : '');
    return '<button type="button" class="host-card ' + (risk >= 70 ? 'risk-critical' : risk >= 40 ? 'risk-high' : '') +
      '" data-action="host" data-ip="' + esc(h.ip) + '">' +
      '<div class="host-card-header"><span class="host-ip">' + esc(h.ip) + '</span>' +
      '<span class="host-risk" style="color:' + riskColor(risk) + '">' + esc(risk) + '</span></div>' +
      '<div class="host-card-body"><div>🖥 ' + esc(hostName(h)) + '</div><div>🏭 ' + esc(h.vendor && h.vendor !== 'Unknown' ? h.vendor : t('unknown_vendor')) +
      '</div><div>💿 ' + esc(h.os_guess && h.os_guess !== 'Unknown' ? h.os_guess : t('unknown_os')) + '</div><div>🔌 ' + esc(h.mac || 'N/A') + '</div></div>' +
      '<div class="host-ports">' + chips + '</div></button>';
  }).join('');
}

function filterHosts() {
  const q = $('hostSearch').value.trim().toLowerCase();
  renderHostsGrid(!q ? state.hosts : state.hosts.filter(h =>
    [h.ip, h.hostname, h.vendor, h.mac, h.os_guess, h.notes].some(v => String(v || '').toLowerCase().includes(q))));
}

async function showHostModal(ip) {
  let h;
  try { h = await api('hosts/' + encodeURIComponent(ip)); } catch (e) { return notify(t('host_not_found'), 'error'); }
  const risk = h.risk_score || 0;
  const ports = Object.entries(h.open_ports || {});
  const vulns = h.vulnerabilities || [];
  const chips = ports.map(([p, s]) => '<span class="port-chip" title="' + esc(s && s.banner || '') + '">' + esc(p) + '/' + esc(s && typeof s === 'object' ? s.service : s) + '</span>').join('') ||
    '<span class="muted">' + esc(t('no_port_scan')) + '</span>';
  const sevColor = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#64748b' };
  const vulnHtml = vulns.map(v => {
    const [desc, fix] = vulnText(v);
    return '<div class="vuln-item" style="border-left-color:' + (sevColor[v.severity] || '#64748b') + '">' +
      '<div class="vuln-item-head"><b>' + esc(v.vuln_type) + ' · ' + esc(v.port) + '/' + esc(v.service) + '</b>' +
      '<span class="badge badge-' + esc(v.severity) + '">' + esc(sevLabel(v.severity)) + '</span></div>' +
      '<div class="vuln-desc">' + esc(desc) + '</div><div class="vuln-fix">💡 ' + esc(fix) + '</div></div>';
  }).join('');
  const item = (k, v, style) => '<div class="detail-item"><div class="detail-key">' + esc(t(k)) + '</div><div class="detail-val"' + (style ? ' style="' + style + '"' : '') + '>' + v + '</div></div>';

  $('modalTitle').textContent = t('host_details', { ip: h.ip });
  $('modalBody').innerHTML =
    '<div class="detail-grid">' +
    item('col_ip', esc(h.ip), 'color:var(--accent)') + item('col_hostname', esc(hostName(h))) +
    item('col_mac', esc(h.mac || '—')) + item('col_vendor', esc(h.vendor || '—')) +
    item('col_os', esc(h.os_guess || '—')) + item('risk_score', esc(risk) + '/100', 'color:' + riskColor(risk) + ';font-weight:700') +
    item('col_status', esc(h.status || 'up'), 'color:var(--green)') + item('last_seen', fmtDate(h.last_seen)) +
    '</div>' +
    '<div class="modal-section"><div class="detail-key">' + esc(t('open_ports_n', { n: ports.length })) + '</div><div class="host-ports">' + chips + '</div></div>' +
    (vulns.length ? '<div class="modal-section"><div class="detail-key">' + esc(t('vulns_n', { n: vulns.length })) + '</div>' + vulnHtml + '</div>' : '') +
    '<div class="modal-section"><div class="detail-key">' + esc(t('notes')) + '</div>' +
    '<textarea class="notes-area" id="hostNotes" maxlength="4000" placeholder="' + esc(t('notes_ph')) + '">' + esc(h.notes || '') + '</textarea>' +
    '<button class="btn-primary btn-sm mt-8" data-action="save-notes" data-ip="' + esc(h.ip) + '">' + esc(t('save_notes')) + '</button></div>' +
    '<div class="modal-actions">' +
    '<button class="btn-secondary btn-sm" data-action="to-ports" data-ip="' + esc(h.ip) + '">' + esc(t('scan_ports_btn')) + '</button>' +
    '<button class="btn-secondary btn-sm" data-action="to-vulns" data-ip="' + esc(h.ip) + '">' + esc(t('check_vulns_btn')) + '</button></div>';
  $('hostModal').classList.add('open');
}

async function saveNotes(ip) {
  try {
    await api('hosts/' + encodeURIComponent(ip) + '/notes', { method: 'POST', body: { notes: $('hostNotes').value } });
    notify(t('notes_saved'));
  } catch (e) { notify(e.message, 'error'); }
}

function closeModal() { $('hostModal').classList.remove('open'); }

// ─── PROGRAMADOR ───
async function loadScheduledTasks() {
  const el = $('scheduledList');
  let tasks = [];
  try { tasks = await api('scheduled'); } catch (e) { /* sin servidor */ }
  if (!tasks.length) { el.innerHTML = emptyState('no_tasks'); return; }
  el.innerHTML = tasks.map(task =>
    '<div class="task-item"><div>' +
    '<div class="task-name">' + esc(task.name) + '</div>' +
    '<div class="task-meta">' + esc(t('type_' + task.scan_type)) + ' → <span class="mono">' + esc(task.target) + '</span> · ' + esc(t('sch_' + task.schedule)) + '</div>' +
    '<div class="task-meta">' + esc(t('task_last', { d: task.last_run ? fmtDate(task.last_run) : t('task_never') })) +
    (task.next_run ? ' · ' + esc(t('task_next', { d: fmtDate(task.next_run) })) : '') + '</div></div>' +
    '<div class="task-buttons"><button class="btn-secondary btn-sm" data-action="run-task" data-id="' + esc(task.id) + '">' + esc(t('run_now')) + '</button>' +
    '<button class="task-del" data-action="del-task" data-id="' + esc(task.id) + '" title="' + esc(t('delete')) + '" aria-label="' + esc(t('delete')) + '">✕</button></div></div>'
  ).join('');
}

async function addScheduledTask() {
  const body = {
    name: $('schedName').value.trim(), scan_type: $('schedType').value,
    target: $('schedTarget').value.trim(), schedule: $('schedInterval').value,
  };
  if (!body.name || !body.target) return notify(t('fill_all'), 'error');
  try {
    await api('scheduled', { method: 'POST', body });
    notify(t('task_added'));
    $('schedName').value = '';
    $('schedTarget').value = '';
  } catch (e) { notify(e.message, 'error'); }
  loadScheduledTasks();
}

async function runTask(id) {
  try {
    const r = await api('scheduled/' + id + '/run', { method: 'POST' });
    notify(t('task_started'));
    const progress = r.scan_type === 'discovery' ? 'discProgress' : r.scan_type === 'ports' ? 'portProgress' : 'vulnProgress';
    pollScan(r.scan_id, progress).then(() => { loadScheduledTasks(); loadDashboard(); });
    loadScheduledTasks();
  } catch (e) { notify(e.message, 'error'); }
}

async function deleteTask(id) {
  try { await api('scheduled/' + id, { method: 'DELETE' }); } catch (e) { notify(e.message, 'error'); }
  loadScheduledTasks();
}

// ─── INFORMES ───
async function loadReportSummary() {
  try {
    const s = await api('stats');
    const items = [['sum_hosts', s.total_hosts, 'var(--accent)'], ['sum_vulns', s.total_vulns, 'var(--text)'],
      ['sum_critical', s.critical, 'var(--red)'], ['sum_high', s.high, 'var(--orange)'],
      ['sum_medium', s.medium, 'var(--yellow)'], ['sum_scans', s.scans, 'var(--text)']];
    $('reportSummary').innerHTML = '<div class="summary-grid">' + items.map(([k, v, c]) =>
      '<div class="summary-item"><div class="summary-num" style="color:' + c + '">' + esc(v) + '</div><div class="summary-label">' + esc(t(k)) + '</div></div>'
    ).join('') + '</div>';
  } catch (e) { /* sin servidor */ }
}

/** Descarga o abre el informe pidiéndolo por fetch (así también funciona en la demo). */
async function getReport(type, preview) {
  const tab = preview ? window.open('', '_blank') : null;
  try {
    const res = await fetch('api/report/' + type + '?lang=' + state.lang + (preview ? '&inline=1' : ''));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const blob = await res.blob();
    const url = URL.createObjectURL(new Blob([blob], { type: type === 'html' ? 'text/html' : 'text/plain' }));
    if (preview) {
      if (tab) tab.location.href = url;
    } else {
      const a = document.createElement('a');
      a.href = url;
      a.download = 'nirvana_lan_report_' + new Date().toISOString().slice(0, 19).replace(/[-:T]/g, '') + '.' + type;
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (e) {
    if (tab) tab.close();
    notify(t('connection_error'), 'error');
  }
}

// ─── ESCANEO RÁPIDO ───
async function quickScan() {
  try {
    const data = await api('network-info');
    const net = data.suggested || (data.networks[0] && data.networks[0].network);
    if (!net) return notify(t('no_network'), 'error');
    notify(t('quick_starting', { net }));
    $('discTarget').value = net;
    switchView('discovery');
    startDiscovery(net);
  } catch (e) { notify(t('no_network'), 'error'); }
}

// ─── EVENTOS (delegados: sin onclick en el HTML, compatible con la CSP) ───
const ACTIONS = {
  theme: () => toggleTheme(),
  lang: () => setLang(state.lang === 'es' ? 'en' : 'es'),
  menu: () => $('sidebar').classList.toggle('open'),
  'quick-scan': () => quickScan(),
  'dismiss-legal': () => { $('legalNote').hidden = true; try { localStorage.setItem('nirvana-legal-ok', '1'); } catch (e) { /* */ } },
  iface: el => { $('discTarget').value = el.dataset.net; renderNetworkHint(); },
  discovery: () => startDiscovery(),
  'clear-hosts': () => clearHosts(),
  'port-scan': () => startPortScan(),
  'to-ports': el => setPortTarget(el.dataset.ip),
  'to-vulns': el => setVulnTarget(el.dataset.ip),
  host: el => showHostModal(el.dataset.ip),
  dns: () => startDNS(),
  smb: () => startSMB(),
  'vuln-scan': () => startVulnScan(),
  'scan-all': () => scanAllHosts(),
  'save-notes': el => saveNotes(el.dataset.ip),
  'close-modal': (el, ev) => { if (ev.target === el) closeModal(); },
  'add-task': () => addScheduledTask(),
  'run-task': el => runTask(el.dataset.id),
  'del-task': el => deleteTask(el.dataset.id),
  report: el => getReport(el.dataset.type, false),
  'report-preview': () => getReport('html', true),
};

document.addEventListener('click', ev => {
  const nav = ev.target.closest('[data-view]');
  if (nav) { ev.preventDefault(); switchView(nav.dataset.view); return; }
  const tab = ev.target.closest('.tab-btn');
  if (tab) {
    const view = tab.closest('.view');
    view.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === tab));
    view.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === 'tab-' + tab.dataset.tab));
    return;
  }
  const sev = ev.target.closest('.filter-btn');
  if (sev) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b === sev));
    state.sevFilter = sev.dataset.sev;
    renderVulnsTable();
    return;
  }
  const el = ev.target.closest('[data-action]');
  if (el && ACTIONS[el.dataset.action]) ACTIONS[el.dataset.action](el, ev);
});

document.addEventListener('keydown', ev => {
  if (ev.key === 'Escape') { closeModal(); $('sidebar').classList.remove('open'); }
  if (ev.key === 'Enter' && ev.target.matches('input.input')) {
    const map = { discTarget: startDiscovery, portTarget: startPortScan, customPorts: startPortScan, dnsTarget: startDNS,
      smbTarget: startSMB, vulnTarget: startVulnScan, schedTarget: addScheduledTask };
    if (map[ev.target.id]) map[ev.target.id]();
  }
});

// ─── INICIO ───
document.addEventListener('DOMContentLoaded', () => {
  applyI18n();
  initTheme();
  initClock();
  try { if (localStorage.getItem('nirvana-legal-ok') === '1') $('legalNote').hidden = true; } catch (e) { /* */ }
  $('portRange').addEventListener('change', function () { $('customPortGroup').hidden = this.value !== 'custom'; });
  $('hostSearch').addEventListener('input', filterHosts);
  $('discTarget').addEventListener('input', renderNetworkHint);
  renderPortsTable(null);
  loadNetworkInfo();
  switchView((location.hash || '#dashboard').slice(1));
  setInterval(() => { if (state.view === 'dashboard') loadDashboard(); }, 30000);
});
