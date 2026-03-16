/* ── NIRVANA LAN — app.js ── */

// ─── STATE ───
let currentView = 'dashboard';
let allHosts = [];
let allVulns = [];
let currentSevFilter = 'ALL';
let detectedNetworks = [];

// ─── INIT ───
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initClock();
  initNavigation();
  initTabs();
  loadNetworkInfo();
  loadDashboard();
  setInterval(loadDashboard, 30000);

  document.getElementById('portRange').addEventListener('change', function() {
    document.getElementById('customPortGroup').style.display =
      this.value === 'custom' ? 'block' : 'none';
  });

  document.getElementById('menuToggle').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
  });

  // Filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      this.classList.add('active');
      currentSevFilter = this.dataset.sev;
      renderVulnsTable();
    });
  });

  // Delegate nav links inside view cards
  document.querySelectorAll('.link[data-view]').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      switchView(el.dataset.view);
    });
  });
});

// ─── THEME ───
function initTheme() {
  const saved = localStorage.getItem('nirvana-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeIcon(saved);
  document.getElementById('themeToggle').addEventListener('click', toggleTheme);
}
function toggleTheme() {
  const curr = document.documentElement.getAttribute('data-theme');
  const next = curr === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('nirvana-theme', next);
  updateThemeIcon(next);
}
function updateThemeIcon(theme) {
  document.getElementById('themeIcon').textContent = theme === 'dark' ? '☀' : '☾';
}

// ─── CLOCK ───
function initClock() {
  function tick() {
    const now = new Date();
    document.getElementById('clock').textContent =
      now.toLocaleTimeString('en-GB', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  }
  tick();
  setInterval(tick, 1000);
}

// ─── NAVIGATION ───
function initNavigation() {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const view = link.dataset.view;
      if (view) switchView(view);
      if (window.innerWidth <= 900) {
        document.getElementById('sidebar').classList.remove('open');
      }
    });
  });
}

function switchView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  const viewEl = document.getElementById('view-' + name);
  const linkEl = document.querySelector('.nav-link[data-view="' + name + '"]');
  if (viewEl) viewEl.classList.add('active');
  if (linkEl) linkEl.classList.add('active');

  const labels = {
    dashboard: 'Dashboard', discovery: 'Network Discovery',
    ports: 'Port Scanner', enumerate: 'Protocol Enumeration',
    vulns: 'Vulnerability Analysis', hosts: 'Host Inventory',
    scheduler: 'Task Scheduler', reports: 'Reports'
  };
  document.getElementById('currentViewLabel').textContent = labels[name] || name;
  currentView = name;

  // Load data for view
  if (name === 'discovery') loadDiscoveryHosts();
  if (name === 'hosts') { loadHostsGrid(); loadQuickButtons(); }
  if (name === 'vulns') loadVulns();
  if (name === 'reports') loadReportSummary();
  if (name === 'scheduler') loadScheduledTasks();
  if (name === 'ports') loadQuickButtons();
}

// ─── TABS ───
function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const tabId = this.dataset.tab;
      const container = this.closest('.view');
      container.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      container.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      this.classList.add('active');
      const tc = document.getElementById('tab-' + tabId);
      if (tc) tc.classList.add('active');
    });
  });
}

// ─── NETWORK INFO ───
async function loadNetworkInfo() {
  try {
    const res = await fetch('/api/network-info');
    const data = await res.json();
    detectedNetworks = data.networks || [];

    if (detectedNetworks.length === 0) {
      document.getElementById('networkHint').textContent =
        'No interface detected. Enter range manually (e.g. 192.168.1.0/24)';
      document.getElementById('networkInfo').textContent = 'Not detected';
      return;
    }

    // Build interface selector if more than one
    const hintEl = document.getElementById('networkHint');
    if (detectedNetworks.length === 1) {
      const n = detectedNetworks[0];
      document.getElementById('discTarget').value = n.network;
      document.getElementById('networkInfo').textContent = n.network;
      hintEl.textContent = 'Detected: ' + n.interface + ' — ' + n.ip + ' (' + n.network + ')';
    } else {
      // Multiple interfaces: show clickable chips
      document.getElementById('discTarget').value = data.suggested || detectedNetworks[0].network;
      document.getElementById('networkInfo').textContent = detectedNetworks[0].network;
      hintEl.innerHTML = 'Select interface: ' +
        detectedNetworks.map(n =>
          '<span class="iface-chip" onclick="selectIface(\'' + n.network + '\',\'' + n.interface + '\')">' +
          n.interface + ' ' + n.network + '</span>'
        ).join(' ');
    }
  } catch(e) {
    document.getElementById('networkHint').textContent = 'Enter network range manually';
  }
}

function selectIface(network, iface) {
  document.getElementById('discTarget').value = network;
  document.getElementById('networkInfo').textContent = network;
  document.querySelectorAll('.iface-chip').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
}

// ─── DASHBOARD ───
async function loadDashboard() {
  try {
    const [statsRes, hostsRes] = await Promise.all([
      fetch('/api/stats'), fetch('/api/hosts')
    ]);
    const stats = await statsRes.json();
    const hosts = await hostsRes.json();
    allHosts = hosts;

    document.getElementById('stat-hosts').textContent = stats.total_hosts;
    document.getElementById('stat-critical').textContent = stats.critical;
    document.getElementById('stat-high').textContent = stats.high;
    document.getElementById('stat-medium').textContent = stats.medium;
    document.getElementById('stat-vulns').textContent = stats.total_vulns;
    document.getElementById('stat-scans').textContent = stats.scans;

    renderTopPortsChart(stats.top_ports);
    renderRiskChart(stats);
    renderRecentHosts(hosts.slice(0, 8));
  } catch(e) { console.error('Dashboard load error:', e); }
}

function renderTopPortsChart(ports) {
  const el = document.getElementById('topPortsChart');
  if (!ports || ports.length === 0) {
    el.innerHTML = '<div class="empty-state">No port data yet. Run a port scan.</div>';
    return;
  }
  const max = ports[0].count || 1;
  el.innerHTML = '<div class="bar-chart">' + ports.map(p =>
    '<div class="bar-row">' +
    '<span class="bar-label">' + p.port + '/' + p.service + '</span>' +
    '<div class="bar-track"><div class="bar-fill" style="width:' + Math.round(p.count/max*100) + '%">' + p.count + '</div></div>' +
    '</div>'
  ).join('') + '</div>';
}

function renderRiskChart(stats) {
  const el = document.getElementById('riskChart');
  const total = stats.total_vulns || 0;
  if (total === 0) {
    el.innerHTML = '<div class="empty-state">No vulnerability data yet</div>';
    return;
  }
  const items = [
    { label: 'Critical', count: stats.critical, color: '#ef4444' },
    { label: 'High',     count: stats.high,     color: '#f97316' },
    { label: 'Medium',   count: stats.medium,   color: '#eab308' },
    { label: 'Low',      count: stats.low,      color: '#3b82f6' },
  ].filter(i => i.count > 0);
  el.innerHTML = '<div class="bar-chart">' + items.map(i =>
    '<div class="bar-row">' +
    '<span class="bar-label" style="color:' + i.color + '">' + i.label + '</span>' +
    '<div class="bar-track"><div class="bar-fill" style="width:' + Math.round(i.count/total*100) + '%;background:' + i.color + '">' + i.count + '</div></div>' +
    '</div>'
  ).join('') + '</div>';
}

function renderRecentHosts(hosts) {
  const el = document.getElementById('recentHostsTable');
  if (!hosts || !hosts.length) {
    el.innerHTML = '<div class="empty-state">No hosts discovered yet. Run a Discovery scan.</div>';
    return;
  }
  let rows = hosts.map(h => {
    const risk = h.risk_score || 0;
    const rcolor = risk >= 70 ? '#ef4444' : risk >= 40 ? '#f97316' : risk >= 20 ? '#eab308' : '#10b981';
    const ports = Object.keys(h.open_ports || {}).slice(0, 5);
    const portHtml = ports.map(p => '<span class="port-chip">' + p + '</span>').join(' ');
    return '<tr>' +
      '<td style="color:var(--accent);cursor:pointer" onclick="showHostModal(\'' + h.ip + '\')">' + h.ip + '</td>' +
      '<td>' + (h.hostname && h.hostname !== h.ip ? h.hostname : '—') + '</td>' +
      '<td>' + (h.os_guess || '—') + '</td>' +
      '<td style="color:' + rcolor + ';font-weight:700">' + risk + '</td>' +
      '<td>' + portHtml + '</td>' +
      '</tr>';
  }).join('');
  el.innerHTML = '<table class="data-table"><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Risk</th><th>Ports</th></tr></thead><tbody>' + rows + '</tbody></table>';
}

// ─── DISCOVERY ───
async function startDiscovery() {
  const target = document.getElementById('discTarget').value.trim();
  if (!target) { notify('Enter a network range (e.g. 192.168.1.0/24)', 'error'); return; }
  if (!target.includes('/')) { notify('Include subnet mask, e.g. 192.168.1.0/24', 'error'); return; }

  const options = {
    os_detect: document.getElementById('osDetect').checked,
    resolve_hostnames: document.getElementById('resolveHostnames').checked,
    vendor_lookup: document.getElementById('vendorLookup').checked,
  };

  const btn = document.getElementById('startDiscovery');
  btn.disabled = true;
  btn.textContent = '⏳ Scanning...';

  // Reset progress panel
  document.getElementById('discProgress').innerHTML =
    '<div class="progress-msg">Starting scan on ' + target + '...</div>';

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type: 'discovery', target: target, options: options})
    });
    const data = await res.json();
    if (data.error) {
      notify(data.error, 'error');
      btn.disabled = false;
      btn.textContent = '▶ Start Discovery Scan';
      return;
    }
    pollScan(data.scan_id, 'discProgress', onDiscoveryUpdate, onDiscoveryDone);
  } catch(e) {
    notify('Failed to start scan: ' + e.message, 'error');
    btn.disabled = false;
    btn.textContent = '▶ Start Discovery Scan';
  }
}

function onDiscoveryUpdate(status) {
  const prog = document.getElementById('discProgress');
  const pct = status.progress || 0;
  const hosts = status.hosts || [];
  const streamHtml = hosts.slice(-15).map(h =>
    '<div class="host-found-entry">▶ ' + h.ip +
    (h.hostname && h.hostname !== h.ip ? ' — ' + h.hostname : '') +
    (h.vendor && h.vendor !== 'Unknown' ? ' [' + h.vendor + ']' : '') +
    '</div>'
  ).join('');
  prog.innerHTML =
    '<div class="progress-msg">' + (status.message || 'Scanning...') + '</div>' +
    '<div class="progress-bar-wrap"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
    '<div class="progress-pct">' + pct + '%</div>' +
    '<div class="found-hosts-stream">' + streamHtml + '</div>';
}

function onDiscoveryDone(status) {
  const btn = document.getElementById('startDiscovery');
  btn.disabled = false;
  btn.textContent = '▶ Start Discovery Scan';
  flashScanComplete();
  const count = (status.hosts || []).length;
  notify('Discovery complete! Found ' + count + ' hosts');
  // Always reload the table after scan
  loadDiscoveryHosts();
  loadDashboard();
}

async function loadDiscoveryHosts() {
  try {
    const res = await fetch('/api/hosts');
    const hosts = await res.json();
    allHosts = hosts;
    const countEl = document.getElementById('discHostCount');
    if (countEl) countEl.textContent = hosts.length;
    const tbody = document.getElementById('discHostsBody');
    if (!tbody) return;
    if (!hosts.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-row">No hosts discovered yet</td></tr>';
      return;
    }
    tbody.innerHTML = hosts.map(h =>
      '<tr>' +
      '<td style="color:var(--accent);font-weight:700">' + h.ip + '</td>' +
      '<td>' + (h.hostname && h.hostname !== h.ip ? h.hostname : '—') + '</td>' +
      '<td>' + (h.mac || '—') + '</td>' +
      '<td>' + (h.vendor || '—') + '</td>' +
      '<td>' + (h.os_guess || '—') + '</td>' +
      '<td><span style="color:' + (h.status === 'up' ? 'var(--green)' : 'var(--red)') + '">' + (h.status || 'up') + '</span></td>' +
      '<td>' +
      '<button class="btn-secondary btn-sm" onclick="setPortTarget(\'' + h.ip + '\')">Scan Ports</button> ' +
      '<button class="btn-secondary btn-sm" onclick="setVulnTarget(\'' + h.ip + '\')">Vulns</button> ' +
      '<button class="btn-secondary btn-sm" onclick="showHostModal(\'' + h.ip + '\')">Details</button>' +
      '</td>' +
      '</tr>'
    ).join('');
  } catch(e) {
    console.error('loadDiscoveryHosts error:', e);
  }
}

async function clearHosts() {
  if (!confirm('Clear all hosts and vulnerabilities from the database?')) return;
  await fetch('/api/hosts/clear', {method: 'POST'});
  notify('All hosts cleared');
  loadDiscoveryHosts();
  loadDashboard();
}

// ─── PORT SCAN ───
async function startPortScan() {
  const target = document.getElementById('portTarget').value.trim();
  if (!target) { notify('Enter a target IP', 'error'); return; }

  let portRange = document.getElementById('portRange').value;
  if (portRange === 'custom') portRange = document.getElementById('customPorts').value.trim();
  if (!portRange) { notify('Enter custom ports', 'error'); return; }

  document.getElementById('portResultTitle').textContent = 'Port Results — ' + target;
  document.getElementById('portCount').textContent = '0';
  document.getElementById('portResultsBody').innerHTML =
    '<tr><td colspan="5" class="empty-row">Scanning...</td></tr>';

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type: 'ports', target: target, port_range: portRange})
    });
    const data = await res.json();
    pollScan(data.scan_id, 'portProgress', null, onPortsDone);
  } catch(e) {
    notify('Failed to start port scan: ' + e.message, 'error');
  }
}

function onPortsDone(status) {
  flashScanComplete();
  const ports = status.ports || [];
  notify('Port scan complete! ' + ports.length + ' open ports found');
  document.getElementById('portCount').textContent = ports.length;

  const HIGH_RISK_PORTS = [21, 23, 135, 137, 139, 445, 1433, 3306, 3389, 5900, 6379, 9200, 27017];
  const tbody = document.getElementById('portResultsBody');
  if (!ports.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No open ports found</td></tr>';
    return;
  }
  const sorted = ports.slice().sort((a, b) => a.port - b.port);
  tbody.innerHTML = sorted.map(p => {
    const risky = HIGH_RISK_PORTS.includes(p.port);
    const badge = risky
      ? '<span class="badge badge-HIGH">High Risk</span>'
      : '<span class="badge badge-INFO">Normal</span>';
    return '<tr' + (risky ? ' style="background:rgba(239,68,68,0.04)"' : '') + '>' +
      '<td style="font-weight:700;color:var(--accent)">' + p.port + '</td>' +
      '<td>' + p.service + '</td>' +
      '<td style="color:var(--green)">OPEN</td>' +
      '<td style="font-size:11px;color:var(--text3);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (p.banner || '—') + '</td>' +
      '<td>' + badge + '</td>' +
      '</tr>';
  }).join('');
}

function setPortTarget(ip) {
  document.getElementById('portTarget').value = ip;
  switchView('ports');
}

// ─── QUICK HOST BUTTONS ───
async function loadQuickButtons() {
  const el = document.getElementById('quickHostButtons');
  if (!el) return;
  try {
    const res = await fetch('/api/hosts');
    const hosts = await res.json();
    if (!hosts.length) {
      el.innerHTML = '<span style="color:var(--text3);font-size:13px">No hosts in inventory yet. Run a discovery scan first.</span>';
      return;
    }
    el.innerHTML = hosts.map(h =>
      '<button class="host-btn" onclick="setPortTarget(\'' + h.ip + '\')">' + h.ip + '</button>'
    ).join('');
  } catch(e) {}
}

// ─── DNS ───
async function startDNS() {
  const target = document.getElementById('dnsTarget').value.trim();
  if (!target) { notify('Enter a domain', 'error'); return; }
  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type: 'dns', target: target})
    });
    const data = await res.json();
    pollScan(data.scan_id, 'dnsProgress', null, status => {
      const results = status.results || {};
      const el = document.getElementById('dnsResults');
      const card = document.getElementById('dnsResultsCard');
      if (card) card.style.display = 'block';
      if (!Object.keys(results).length) {
        el.innerHTML = '<div class="empty-state">No DNS records found</div>';
        return;
      }
      el.innerHTML = Object.entries(results).map(([type, vals]) =>
        '<div class="dns-record">' +
        '<div class="dns-type">' + type + '</div>' +
        '<div class="dns-values">' +
        (Array.isArray(vals) ? vals : [vals]).map(v => '<div class="dns-val">' + v + '</div>').join('') +
        '</div></div>'
      ).join('');
      notify('DNS enumeration complete');
    });
  } catch(e) { notify('Failed to start DNS scan', 'error'); }
}

// ─── SMB ───
async function startSMB() {
  const target = document.getElementById('smbTarget').value.trim();
  if (!target) { notify('Enter a target IP', 'error'); return; }
  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type: 'smb', target: target})
    });
    const data = await res.json();
    pollScan(data.scan_id, 'smbProgress', null, status => {
      const results = status.results || {};
      const el = document.getElementById('smbResults');
      const card = document.getElementById('smbResultsCard');
      if (card) card.style.display = 'block';
      if (!results.port_open) {
        el.innerHTML = '<div class="empty-state">SMB ports (139/445) not open on this host</div>';
        return;
      }
      let html = '';
      if (results.shares && results.shares.length) {
        html += '<div class="dns-record"><div class="dns-type">Shared Resources</div><div class="dns-values">' +
          results.shares.map(s => '<div class="dns-val">📁 ' + s.name + ' (' + s.type + ')</div>').join('') +
          '</div></div>';
      } else {
        html += '<div class="dns-record"><div class="dns-type">Shares</div><div class="dns-values"><div class="dns-val">None found or access denied</div></div></div>';
      }
      if (results.users && results.users.length) {
        html += '<div class="dns-record"><div class="dns-type">Users</div><div class="dns-values">' +
          results.users.map(u => '<div class="dns-val">👤 ' + u + '</div>').join('') +
          '</div></div>';
      }
      if (results.banner) {
        html += '<div class="dns-record"><div class="dns-type">Banner</div><div class="dns-values"><div class="dns-val">' + results.banner + '</div></div></div>';
      }
      el.innerHTML = html || '<div class="empty-state">No SMB data retrieved</div>';
      notify('SMB enumeration complete');
    });
  } catch(e) { notify('Failed to start SMB scan', 'error'); }
}

// ─── VULNS ───
function setVulnTarget(ip) {
  document.getElementById('vulnTarget').value = ip;
  switchView('vulns');
}

async function startVulnScan() {
  const target = document.getElementById('vulnTarget').value.trim();
  if (!target) { notify('Enter a target IP', 'error'); return; }
  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type: 'vulns', target: target})
    });
    const data = await res.json();
    pollScan(data.scan_id, 'vulnProgress', null, status => {
      flashScanComplete();
      notify('Vuln scan done. Risk score: ' + (status.risk_score || 0));
      loadVulns();
    });
  } catch(e) { notify('Failed to start vuln scan', 'error'); }
}

async function scanAllHosts() {
  const res = await fetch('/api/hosts');
  const hosts = await res.json();
  if (!hosts.length) { notify('No hosts in inventory. Run discovery first.', 'error'); return; }
  notify('Queuing vuln scans for ' + hosts.length + ' hosts...');
  for (const host of hosts) {
    await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type: 'vulns', target: host.ip})
    });
  }
  notify('All ' + hosts.length + ' host scans queued!');
  setTimeout(loadVulns, 3000);
}

async function loadVulns() {
  try {
    const res = await fetch('/api/vulnerabilities');
    allVulns = await res.json();
    renderVulnsTable();
  } catch(e) {}
}

function renderVulnsTable() {
  const tbody = document.getElementById('vulnsBody');
  const vulns = currentSevFilter === 'ALL' ? allVulns :
    allVulns.filter(v => v.severity === currentSevFilter);
  if (!vulns.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-row">No ' +
      (currentSevFilter !== 'ALL' ? currentSevFilter + ' ' : '') + 'vulnerabilities found</td></tr>';
    return;
  }
  tbody.innerHTML = vulns.map(v =>
    '<tr>' +
    '<td style="color:var(--accent);cursor:pointer" onclick="showHostModal(\'' + v.host_ip + '\')">' + v.host_ip + '</td>' +
    '<td>' + v.port + '</td>' +
    '<td>' + v.service + '</td>' +
    '<td style="font-weight:700">' + v.vuln_type + '</td>' +
    '<td><span class="badge badge-' + v.severity + '">' + v.severity + '</span></td>' +
    '<td style="max-width:250px;font-size:11px;line-height:1.4">' + v.description + '</td>' +
    '<td style="max-width:200px;font-size:11px;color:var(--green);line-height:1.4">' + v.recommendation + '</td>' +
    '</tr>'
  ).join('');
}

// ─── HOST INVENTORY ───
async function loadHostsGrid() {
  try {
    const res = await fetch('/api/hosts');
    allHosts = await res.json();
    renderHostsGrid(allHosts);
  } catch(e) {}
}

function renderHostsGrid(hosts) {
  const el = document.getElementById('hostsGrid');
  if (!hosts || !hosts.length) {
    el.innerHTML = '<div class="empty-state">No hosts in inventory. Run a discovery scan.</div>';
    return;
  }
  const RISKY_PORTS = [21, 23, 445, 3389, 5900, 6379, 9200, 27017];
  el.innerHTML = hosts.map(h => {
    const risk = h.risk_score || 0;
    const riskClass = risk >= 70 ? 'risk-critical' : risk >= 40 ? 'risk-high' : '';
    const rcolor = risk >= 70 ? '#ef4444' : risk >= 40 ? '#f97316' : risk >= 20 ? '#eab308' : '#10b981';
    const ports = Object.entries(h.open_ports || {});
    const portChips = ports.slice(0, 8).map(entry => {
      const p = entry[0];
      const s = entry[1];
      const svc = typeof s === 'object' ? s.service : s;
      const risky = RISKY_PORTS.includes(parseInt(p));
      return '<span class="port-chip ' + (risky ? 'risky' : '') + '">' + p + '/' + svc + '</span>';
    }).join('');
    const more = ports.length > 8 ? '<span class="port-chip">+' + (ports.length - 8) + '</span>' : '';
    return '<div class="host-card ' + riskClass + '" onclick="showHostModal(\'' + h.ip + '\')">' +
      '<div class="host-card-header">' +
      '<span class="host-ip">' + h.ip + '</span>' +
      '<span style="font-size:13px;font-weight:700;color:' + rcolor + ';font-family:var(--font-mono)">' + risk + '</span>' +
      '</div>' +
      '<div class="host-card-body">' +
      '<div>🖥 ' + (h.hostname && h.hostname !== h.ip ? h.hostname : '—') + '</div>' +
      '<div>🏭 ' + (h.vendor || 'Unknown vendor') + '</div>' +
      '<div>💿 ' + (h.os_guess || 'Unknown OS') + '</div>' +
      '<div>🔌 ' + (h.mac || 'N/A') + '</div>' +
      '</div>' +
      '<div class="host-ports">' + portChips + more + '</div>' +
      '</div>';
  }).join('');
}

function filterHosts() {
  const q = document.getElementById('hostSearch').value.toLowerCase();
  if (!q) { renderHostsGrid(allHosts); return; }
  const filtered = allHosts.filter(h =>
    h.ip.includes(q) ||
    (h.hostname || '').toLowerCase().includes(q) ||
    (h.vendor || '').toLowerCase().includes(q) ||
    (h.mac || '').toLowerCase().includes(q)
  );
  renderHostsGrid(filtered);
}

// ─── HOST MODAL ───
async function showHostModal(ip) {
  try {
    const res = await fetch('/api/hosts/' + ip);
    const h = await res.json();
    if (h.error) { notify('Host not found', 'error'); return; }

    const risk = h.risk_score || 0;
    const rcolor = risk >= 70 ? '#ef4444' : risk >= 40 ? '#f97316' : risk >= 20 ? '#eab308' : '#10b981';
    const ports = Object.entries(h.open_ports || {});
    const vulns = h.vulnerabilities || [];

    const portChips = ports.map(entry => {
      const p = entry[0];
      const s = entry[1];
      const svc = typeof s === 'object' ? s.service : s;
      return '<span class="port-chip">' + p + '/' + svc + '</span>';
    }).join('') || '<span style="color:var(--text3);font-size:12px">No port data — run a port scan</span>';

    const vulnHtml = vulns.length ? vulns.map(v => {
      const bc = v.severity === 'CRITICAL' ? '#ef4444' : v.severity === 'HIGH' ? '#f97316' : v.severity === 'MEDIUM' ? '#eab308' : '#3b82f6';
      return '<div style="background:var(--bg3);border-radius:7px;padding:10px;margin-bottom:8px;border-left:3px solid ' + bc + '">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">' +
        '<span style="font-weight:700;font-size:13px">' + v.vuln_type + '</span>' +
        '<span class="badge badge-' + v.severity + '">' + v.severity + '</span>' +
        '</div>' +
        '<div style="font-size:11px;color:var(--text2);margin-bottom:4px">' + v.description + '</div>' +
        '<div style="font-size:11px;color:var(--green)">💡 ' + v.recommendation + '</div>' +
        '</div>';
    }).join('') : '';

    document.getElementById('modalTitle').textContent = 'Host Details — ' + ip;
    document.getElementById('modalBody').innerHTML =
      '<div class="detail-grid">' +
      '<div class="detail-item"><div class="detail-key">IP Address</div><div class="detail-val" style="color:var(--accent)">' + h.ip + '</div></div>' +
      '<div class="detail-item"><div class="detail-key">Hostname</div><div class="detail-val">' + (h.hostname || '—') + '</div></div>' +
      '<div class="detail-item"><div class="detail-key">MAC Address</div><div class="detail-val">' + (h.mac || '—') + '</div></div>' +
      '<div class="detail-item"><div class="detail-key">Vendor</div><div class="detail-val">' + (h.vendor || '—') + '</div></div>' +
      '<div class="detail-item"><div class="detail-key">OS Guess</div><div class="detail-val">' + (h.os_guess || '—') + '</div></div>' +
      '<div class="detail-item"><div class="detail-key">Risk Score</div><div class="detail-val" style="color:' + rcolor + ';font-weight:700">' + risk + '/100</div></div>' +
      '<div class="detail-item"><div class="detail-key">Status</div><div class="detail-val" style="color:var(--green)">' + (h.status || 'up') + '</div></div>' +
      '<div class="detail-item"><div class="detail-key">Last Seen</div><div class="detail-val">' + (h.last_seen ? h.last_seen.split('T')[0] : '—') + '</div></div>' +
      '</div>' +
      '<div style="margin-bottom:18px">' +
      '<div class="detail-key" style="margin-bottom:8px">OPEN PORTS (' + ports.length + ')</div>' +
      '<div class="host-ports">' + portChips + '</div>' +
      '</div>' +
      (vulns.length ? '<div style="margin-bottom:18px"><div class="detail-key" style="margin-bottom:8px">VULNERABILITIES (' + vulns.length + ')</div>' + vulnHtml + '</div>' : '') +
      '<div>' +
      '<div class="detail-key" style="margin-bottom:8px">NOTES</div>' +
      '<textarea class="notes-area" id="hostNotes" placeholder="Add notes about this host...">' + (h.notes || '') + '</textarea>' +
      '<button class="btn-primary btn-sm" style="margin-top:8px" onclick="saveNotes(\'' + ip + '\')">💾 Save Notes</button>' +
      '</div>' +
      '<div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap">' +
      '<button class="btn-secondary btn-sm" onclick="setPortTarget(\'' + ip + '\');closeModal()">🔍 Scan Ports</button>' +
      '<button class="btn-secondary btn-sm" onclick="setVulnTarget(\'' + ip + '\');closeModal()">⚠ Check Vulns</button>' +
      '</div>';

    document.getElementById('hostModal').classList.add('open');
  } catch(e) {
    notify('Error loading host details', 'error');
  }
}

async function saveNotes(ip) {
  const notes = document.getElementById('hostNotes').value;
  await fetch('/api/hosts/' + ip + '/notes', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({notes: notes})
  });
  notify('Notes saved');
}

function closeModal() {
  document.getElementById('hostModal').classList.remove('open');
}

// ─── SCHEDULER ───
async function loadScheduledTasks() {
  try {
    const res = await fetch('/api/scheduled');
    const tasks = await res.json();
    const el = document.getElementById('scheduledList');
    if (!tasks.length) {
      el.innerHTML = '<div class="empty-state">No scheduled tasks</div>';
      return;
    }
    el.innerHTML = tasks.map(t =>
      '<div class="task-item">' +
      '<div>' +
      '<div class="task-name">' + t.name + '</div>' +
      '<div class="task-meta">' + t.scan_type + ' → ' + t.target + ' | ' + t.schedule + '</div>' +
      '</div>' +
      '<button class="task-del" onclick="deleteTask(' + t.id + ')">✕</button>' +
      '</div>'
    ).join('');
  } catch(e) {}
}

async function addScheduledTask() {
  const data = {
    name: document.getElementById('schedName').value.trim(),
    scan_type: document.getElementById('schedType').value,
    target: document.getElementById('schedTarget').value.trim(),
    schedule: document.getElementById('schedInterval').value,
  };
  if (!data.name || !data.target) { notify('Fill all fields', 'error'); return; }
  await fetch('/api/scheduled', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  });
  notify('Task scheduled!');
  loadScheduledTasks();
}

async function deleteTask(id) {
  await fetch('/api/scheduled/' + id, {method: 'DELETE'});
  loadScheduledTasks();
}

// ─── REPORTS ───
async function loadReportSummary() {
  try {
    const res = await fetch('/api/stats');
    const stats = await res.json();
    const items = [
      {label:'Total Hosts', val:stats.total_hosts, color:'var(--accent)'},
      {label:'Vulnerabilities', val:stats.total_vulns, color:'var(--text)'},
      {label:'Critical', val:stats.critical, color:'var(--red)'},
      {label:'High', val:stats.high, color:'var(--orange)'},
      {label:'Medium', val:stats.medium, color:'var(--yellow)'},
      {label:'Scans Run', val:stats.scans, color:'var(--text)'},
    ];
    document.getElementById('reportSummary').innerHTML =
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px">' +
      items.map(s =>
        '<div style="background:var(--bg3);border-radius:8px;padding:16px;text-align:center">' +
        '<div style="font-size:28px;font-weight:800;color:' + s.color + ';font-family:var(--font-mono)">' + s.val + '</div>' +
        '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-top:4px">' + s.label + '</div>' +
        '</div>'
      ).join('') +
      '</div>';
  } catch(e) {}
}

function downloadReport(type) {
  window.open('/api/report/' + type, '_blank');
}
function previewReport() {
  window.open('/api/report/html', '_blank');
}

// ─── QUICK SCAN ───
async function quickScan() {
  try {
    const res = await fetch('/api/network-info');
    const data = await res.json();
    const net = data.suggested || (data.networks[0] && data.networks[0].network);
    if (!net) { notify('Could not detect network', 'error'); return; }
    notify('⚡ Starting quick scan of ' + net + '...');
    const scanRes = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type: 'discovery', target: net, options: {os_detect: true, resolve_hostnames: true, vendor_lookup: true}})
    });
    const scanData = await scanRes.json();
    switchView('discovery');
    // Small delay to let the DOM switch
    setTimeout(() => {
      pollScan(scanData.scan_id, 'discProgress', onDiscoveryUpdate, onDiscoveryDone);
    }, 100);
  } catch(e) {
    notify('Quick scan failed: ' + e.message, 'error');
  }
}

// ─── POLL SCAN ───
function pollScan(scanId, progressElId, onUpdate, onDone) {
  const progEl = document.getElementById(progressElId);
  let finished = false;

  const poll = setInterval(async () => {
    if (finished) return;
    try {
      const res = await fetch('/api/scan/status/' + scanId);
      const status = await res.json();
      const isDone = status.status === 'done' || status.status === 'error';

      if (!isDone) {
        // Still running — update progress
        if (onUpdate) {
          onUpdate(status);
        } else {
          const pct = status.progress || 0;
          if (progEl) progEl.innerHTML =
            '<div class="progress-msg">' + (status.message || 'Scanning...') + '</div>' +
            '<div class="progress-bar-wrap"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
            '<div class="progress-pct">' + pct + '%</div>';
        }
      } else {
        // Done — stop polling first, then handle result
        finished = true;
        clearInterval(poll);

        if (status.status === 'error') {
          if (progEl) progEl.innerHTML =
            '<div style="color:var(--red);font-family:var(--font-mono);font-size:13px">⚠ ' + (status.message || 'Scan failed') + '</div>';
          notify('Scan error: ' + (status.message || 'unknown'), 'error');
        } else {
          // Show final 100% state
          const finalMsg = status.message || 'Scan complete';
          if (progEl) {
            const hosts = status.hosts || [];
            const streamHtml = hosts.slice(-20).map(h =>
              '<div class="host-found-entry">▶ ' + h.ip +
              (h.hostname && h.hostname !== h.ip ? ' — ' + h.hostname : '') +
              '</div>'
            ).join('');
            progEl.innerHTML =
              '<div class="progress-msg" style="color:var(--green)">✓ ' + finalMsg + '</div>' +
              '<div class="progress-bar-wrap"><div class="progress-bar" style="width:100%"></div></div>' +
              '<div class="progress-pct" style="color:var(--green)">100%</div>' +
              (streamHtml ? '<div class="found-hosts-stream">' + streamHtml + '</div>' : '');
          }
          if (onDone) onDone(status);
        }
      }
    } catch(e) {
      finished = true;
      clearInterval(poll);
      if (progEl) progEl.innerHTML = '<div style="color:var(--red)">Connection error</div>';
    }
  }, 1000);
}

// ─── NOTIFY ───
function notify(msg, type) {
  const el = document.getElementById('notification');
  el.textContent = msg;
  el.className = 'notification show' + (type === 'error' ? ' error' : '');
  clearTimeout(el._timeout);
  el._timeout = setTimeout(() => el.classList.remove('show'), 4000);
}

// ─── SCAN COMPLETE FLASH ───
function flashScanComplete() {
  const div = document.createElement('div');
  div.className = 'scan-complete-flash';
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 900);
}
