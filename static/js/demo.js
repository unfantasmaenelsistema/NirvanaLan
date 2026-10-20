/* ── NIRVANA LAN — modo demo (GitHub Pages) ──
   Sustituye la API de Flask por una red de laboratorio ficticia que vive en
   memoria. No se envía nada a ningún sitio y no se escanea ninguna red real.
   Las reglas de hallazgos son las mismas que usa app.py. */
'use strict';

(function () {
  const LAB_NET = '192.168.50.0/24';
  const MY_IP = '192.168.50.23';
  const DOMAIN = 'ghostlab.local';

  // ── Red ficticia ─────────────────────────────────────────
  // Puertos: {puerto: banner}. Las MAC son inventadas (prefijo del fabricante + resto aleatorio fijo).
  const LAB = [
    { ip: '192.168.50.1', mac: 'f4:ec:38:1a:2b:01', hostname: 'router.' + DOMAIN, vendor: 'TP-Link', ttl: 64,
      ports: { 53: '', 80: 'HTTP/1.1 200 OK | Server: lighttpd/1.4.35', 443: '' }, snmp: 'TP-Link Archer C7 Linux 2.6.36' },
    { ip: '192.168.50.10', mac: '00:11:32:4c:9d:10', hostname: 'nas.' + DOMAIN, vendor: 'Synology', ttl: 64,
      ports: { 22: 'SSH-2.0-OpenSSH_8.2p1', 80: 'HTTP/1.1 200 OK | Server: nginx', 139: '', 445: '', 5000: 'HTTP/1.1 200 OK | Server: nginx' },
      shares: [['homes', 'Disk'], ['backup', 'Disk'], ['IPC$', 'IPC']] },
    { ip: '192.168.50.15', mac: '3c:52:82:7e:00:15', hostname: 'printer.' + DOMAIN, vendor: 'HP', ttl: 255,
      ports: { 80: 'HTTP/1.1 200 OK | Server: HP HTTP Server', 515: '', 631: '', 9100: '' } },
    { ip: MY_IP, mac: '00:1b:21:aa:50:23', hostname: 'ghost-pc.' + DOMAIN, vendor: 'Intel', ttl: 128,
      ports: { 135: '', 139: '', 445: '', 3389: '' }, shares: [['IPC$', 'IPC']] },
    { ip: '192.168.50.30', mac: '00:14:22:30:0c:30', hostname: 'intranet.' + DOMAIN, vendor: 'Dell', ttl: 64,
      ports: { 22: 'SSH-2.0-OpenSSH_5.3', 80: 'HTTP/1.1 200 OK | Server: Apache/2.2.15 (CentOS)', 3306: '' } },
    { ip: '192.168.50.41', mac: '50:c7:bf:41:ca:41', hostname: 'cam-entrada.' + DOMAIN, vendor: 'TP-Link', ttl: 64,
      ports: { 23: '', 80: 'HTTP/1.0 200 OK | Server: thttpd/2.25b', 554: '' } },
    { ip: '192.168.50.50', mac: '08:00:27:de:50:50', hostname: 'devbox.' + DOMAIN, vendor: 'VirtualBox', ttl: 64,
      ports: { 22: 'SSH-2.0-OpenSSH_9.6p1', 6379: '', 8080: 'HTTP/1.1 404 Not Found | Server: Werkzeug/3.0.1', 27017: '' } },
    { ip: '192.168.50.60', mac: 'dc:a6:32:60:be:60', hostname: 'raspberrypi.' + DOMAIN, vendor: 'Raspberry Pi', ttl: 64,
      ports: { 22: 'SSH-2.0-OpenSSH_7.9p1 Raspbian', 1883: '', 5900: 'RFB 003.008' } },
    { ip: '192.168.50.77', mac: '52:54:00:77:f7:77', hostname: 'ftp-viejo.' + DOMAIN, vendor: 'QEMU/KVM', ttl: 64,
      ports: { 21: '220 (vsFTPd 2.3.4)', 22: 'SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1', 10000: 'HTTP/1.0 200 Document follows | Server: MiniServ/1.580' } },
    { ip: '192.168.50.101', mac: '92:3e:5a:11:01:01', hostname: '192.168.50.101', vendor: 'Locally administered', ttl: 64, ports: {} },
    { ip: '192.168.50.102', mac: 'a6:10:9f:22:01:02', hostname: '192.168.50.102', vendor: 'Locally administered', ttl: 64, ports: {} },
    { ip: '192.168.50.120', mac: '54:60:09:12:01:20', hostname: 'tv-salon.' + DOMAIN, vendor: 'Google', ttl: 64,
      ports: { 8008: 'HTTP/1.1 404 Not Found', 8443: '' } },
  ];

  const SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 53: 'DNS', 80: 'HTTP', 135: 'MSRPC', 139: 'NetBIOS/SMB', 443: 'HTTPS', 445: 'SMB',
    515: 'LPD', 554: 'RTSP', 631: 'IPP', 1883: 'MQTT', 3306: 'MySQL', 3389: 'RDP', 5000: 'HTTP dev', 5900: 'VNC',
    6379: 'Redis', 8008: 'HTTP', 8080: 'HTTP proxy', 8443: 'HTTPS alt', 9100: 'JetDirect', 10000: 'Webmin', 27017: 'MongoDB',
  };
  const COMMON = [21, 22, 23, 25, 53, 69, 80, 110, 111, 119, 135, 139, 143, 389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 636,
    873, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2222, 3000, 3306, 3389, 3690, 4443, 5000, 5432, 5900,
    5985, 5986, 6379, 7070, 8000, 8080, 8443, 8888, 9000, 9090, 9100, 9200, 10000, 11211, 27017];

  const VULN_CHECKS = [
    [23, 'Telnet', 'TELNET_OPEN', 'CRITICAL', 'Telnet transmits data in plaintext, including credentials. Highly vulnerable to MITM attacks.', 'Disable Telnet immediately. Use SSH instead.'],
    [21, 'FTP', 'FTP_OPEN', 'HIGH', 'FTP transmits credentials and data unencrypted.', 'Use SFTP or FTPS. Disable anonymous access.'],
    [445, 'SMB', 'SMB_OPEN', 'HIGH', 'SMB port exposed. Vulnerable to EternalBlue (MS17-010) and related exploits if unpatched.', 'Ensure system is fully patched. Enable SMB signing. Block if not needed.'],
    [3389, 'RDP', 'RDP_OPEN', 'HIGH', 'RDP exposed to network. Susceptible to BlueKeep (CVE-2019-0708) and brute force.', 'Restrict access via VPN. Enable NLA. Keep patched.'],
    [1433, 'MSSQL', 'MSSQL_OPEN', 'HIGH', 'MSSQL database port exposed. Risk of credential attacks.', 'Restrict access. Disable SA account. Use strong passwords.'],
    [3306, 'MySQL', 'MYSQL_OPEN', 'HIGH', 'MySQL database exposed to network. Risk of unauthorized access.', 'Bind to localhost only. Use strong credentials.'],
    [27017, 'MongoDB', 'MONGODB_OPEN', 'CRITICAL', 'MongoDB may be running without authentication.', 'Enable authentication. Bind to specific interfaces only.'],
    [6379, 'Redis', 'REDIS_OPEN', 'CRITICAL', 'Redis often has no authentication by default. Full data access risk.', 'Enable requirepass/ACLs. Restrict network access.'],
    [11211, 'Memcached', 'MEMCACHED_OPEN', 'HIGH', 'Memcached has no authentication and can leak cached data or be abused for amplification.', 'Bind to localhost and disable UDP.'],
    [5900, 'VNC', 'VNC_OPEN', 'HIGH', 'VNC exposes desktop remotely. Often weakly authenticated.', 'Use strong password. Tunnel through SSH. Restrict access.'],
    [9200, 'Elasticsearch', 'ELASTICSEARCH_OPEN', 'CRITICAL', 'Elasticsearch may be accessible without authentication, exposing all indexed data.', 'Enable security features. Restrict to localhost.'],
    [80, 'HTTP', 'HTTP_OPEN', 'LOW', 'HTTP transmits data unencrypted.', 'Migrate to HTTPS. Implement HSTS.'],
    [22, 'SSH', 'SSH_OPEN', 'INFO', 'SSH service detected. Verify key-based auth and disable root login.', 'Use key-based auth. Disable password auth.'],
  ];
  const BANNER_CHECKS = [
    [/Apache\/2\.[0-2]\./i, 'OUTDATED_APACHE', 'HIGH', 'Outdated Apache version detected.', 'Update to the latest Apache 2.4.x.'],
    [/OpenSSH_[2-6]\./i, 'OUTDATED_OPENSSH', 'HIGH', 'Old OpenSSH version detected.', 'Update OpenSSH to the latest version.'],
    [/Microsoft-IIS\/[5-7]\./i, 'OUTDATED_IIS', 'HIGH', 'Outdated IIS detected.', 'Update IIS or migrate to a supported Windows Server.'],
    [/vsftpd 2\.3\.4/i, 'VSFTPD_BACKDOOR', 'CRITICAL', 'vsftpd 2.3.4 (backdoored release, CVE-2011-2523).', 'Replace vsftpd immediately.'],
    [/vsftpd 2\.[0-3]/i, 'OUTDATED_VSFTPD', 'MEDIUM', 'Old vsftpd version.', 'Update vsftpd.'],
    [/MiniServ/i, 'WEBMIN_DETECTED', 'MEDIUM', 'Webmin detected. Check for known vulnerabilities.', 'Update Webmin regularly and restrict access.'],
  ];
  const WEIGHT = { CRITICAL: 40, HIGH: 20, MEDIUM: 10, LOW: 5, INFO: 1 };
  const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

  // ── Estado en memoria ────────────────────────────────────
  // Se guarda en sessionStorage: sobrevive a recargar la pestaña, desaparece al cerrarla
  let db = { hosts: {}, vulns: [], scans: 0, tasks: [], taskSeq: 0 };
  try { const saved = JSON.parse(sessionStorage.getItem('nirvana-demo-db')); if (saved && saved.hosts) db = saved; } catch (err) { /* sin almacenamiento */ }
  const persist = () => { try { sessionStorage.setItem('nirvana-demo-db', JSON.stringify(db)); } catch (err) { /* sin almacenamiento */ } };
  const jobs = {};
  const byIp = ip => LAB.find(h => h.ip === ip);
  const now = () => new Date().toISOString();

  // ── Utilidades IPv4 ──────────────────────────────────────
  const ipNum = ip => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
  const isIp = v => /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(String(v).trim());
  function parseNet(v) {
    const m = String(v).trim().match(/^([\d.]+)\/(\d{1,2})$/);
    if (!m || !isIp(m[1]) || +m[2] > 32) throw bad('err_bad_network', { value: String(v).slice(0, 60) });
    const prefix = +m[2];
    const size = Math.pow(2, 32 - prefix);
    if (size - 2 > 1024) throw bad('err_range_too_big', { hosts: size - 2, max: 1024 });
    const base = ipNum(m[1]) - (ipNum(m[1]) % size);
    return { prefix, base, size, total: Math.max(size - 2, 1), contains: ip => ipNum(ip) >= base && ipNum(ip) < base + size, str: numIp(base) + '/' + prefix };
  }
  const numIp = n => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255].join('.');
  function parseIp(v) { if (!isIp(v)) throw bad('err_bad_ip', { value: String(v).slice(0, 60) }); return String(v).trim(); }
  function parsePorts(spec) {
    spec = String(spec || 'common').trim().toLowerCase();
    if (spec === 'common') return COMMON;
    if (spec === 'top1000') return range(1, 1000);
    if (spec === 'full') return range(1, 65535);
    const out = new Set();
    for (const part of spec.split(',').map(s => s.trim()).filter(Boolean)) {
      const m = part.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
      const a = m && +m[1], b = m && +(m[2] || m[1]);
      if (!m || a < 1 || b > 65535 || a > b) throw bad('err_bad_ports', { value: part.slice(0, 30) });
      for (let p = a; p <= b; p++) out.add(p);
    }
    if (!out.size) throw bad('err_bad_ports', { value: spec.slice(0, 30) });
    return [...out].sort((x, y) => x - y);
  }
  const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
  function bad(key, params) { const e = new Error(key); e.key = key; e.params = params || {}; return e; }

  function osGuess(ttl) { return ttl <= 64 ? 'Linux/Unix/macOS (TTL≤64)' : ttl <= 128 ? 'Windows (TTL≤128)' : 'Network device (TTL≤255)'; }

  function hostRecord(lab, opts) {
    const prev = db.hosts[lab.ip] || {};
    return Object.assign({ id: Object.keys(db.hosts).length + 1, open_ports: {}, risk_score: 0, notes: '' }, prev, {
      ip: lab.ip, mac: lab.mac,
      hostname: opts.resolve_hostnames === false ? lab.ip : lab.hostname,
      vendor: opts.vendor_lookup === false ? 'Unknown' : lab.vendor,
      os_guess: opts.os_detect ? osGuess(lab.ttl) : (prev.os_guess || 'Unknown'),
      status: 'up', last_seen: now(),
    });
  }

  function vulnsFor(ip) {
    const lab = byIp(ip);
    const h = db.hosts[ip];
    const ports = h ? Object.keys(h.open_ports).map(Number) : [];
    const out = [];
    const found = now();
    for (const [port, service, id, sev, desc, rec] of VULN_CHECKS) {
      if (ports.includes(port)) out.push({ host_ip: ip, port, service, vuln_type: id, severity: sev, description: desc, recommendation: rec, found_at: found });
    }
    for (const port of ports) {
      const banner = (h.open_ports[port] || {}).banner || '';
      for (const [re, id, sev, desc, rec] of BANNER_CHECKS) {
        if (re.test(banner)) {
          out.push({ host_ip: ip, port, service: SERVICES[port] || 'unknown', vuln_type: id, severity: sev,
            description: desc + ' Banner: ' + banner.slice(0, 100), recommendation: rec, found_at: found });
          break;
        }
      }
    }
    if (lab && lab.snmp) {
      out.push({ host_ip: ip, port: 161, service: 'SNMP', vuln_type: 'SNMP_PUBLIC', severity: 'HIGH',
        description: 'SNMP answers with the default community "public" (sysDescr: ' + lab.snmp + ').',
        recommendation: 'Change the community string or move to SNMPv3 with authentication.', found_at: found });
    }
    return out;
  }

  // ── Trabajos simulados (avanzan con el tiempo) ───────────
  function launch(type, target, options, portRange) {
    let job;
    if (type === 'discovery') {
      const net = parseNet(target);
      const hosts = LAB.filter(h => net.contains(h.ip));
      job = { type, duration: 6500, total: net.total, hosts, options: options || {}, target: net.str };
    } else if (type === 'ports') {
      const ip = parseIp(target);
      const ports = parsePorts(portRange);
      const lab = byIp(ip);
      const open = lab ? ports.filter(p => p in lab.ports) : [];
      job = { type, ip, ports, open, lab, duration: Math.min(9000, 1800 + ports.length * 0.12) };
    } else if (type === 'vulns') {
      job = { type, ip: parseIp(target), duration: 2600 };
    } else if (type === 'smb') {
      job = { type, ip: parseIp(target), duration: 1500 };
    } else if (type === 'dns') {
      const d = String(target).trim().toLowerCase().replace(/\.$/, '');
      if (!/^(?=.{1,253}$)(?!-)([a-z0-9_-]{1,63}\.)*[a-z0-9-]{1,63}$/.test(d)) throw bad('err_bad_domain', { value: d.slice(0, 60) });
      job = { type, domain: d, duration: 1200 };
    } else {
      throw bad('err_unknown_type');
    }
    const id = Math.random().toString(16).slice(2, 14);
    job.start = Date.now();
    job.finished = false;
    jobs[id] = job;
    return id;
  }

  function status(id) {
    const job = jobs[id];
    if (!job) return { status: 'not_found' };
    const p = Math.min(1, (Date.now() - job.start) / job.duration);
    const pct = Math.round(p * 100);
    const done = p >= 1;
    if (done && !job.finished) finish(job);

    if (job.type === 'discovery') {
      const seen = job.hosts.slice(0, Math.floor(job.hosts.length * Math.max(0, (p - 0.35) / 0.65)));
      const hosts = (done ? job.hosts : seen).map(h => hostRecord(h, job.options));
      if (done) return { status: 'done', progress: 100, hosts, msg: 'p_discovery_done', params: { n: hosts.length } };
      if (p < 0.3) return { status: 'running', progress: pct, hosts: [], msg: 'p_probing', params: { n: job.total } };
      return { status: 'running', progress: pct, hosts, msg: 'p_scanned',
        params: { done: Math.round(job.total * p), total: job.total, found: hosts.length } };
    }
    if (job.type === 'ports') {
      const visible = job.open.filter((_, i) => (i + 1) / (job.open.length + 1) <= p || done);
      const ports = visible.map(port => ({ port, service: SERVICES[port] || 'unknown', banner: job.lab.ports[port] || '' }));
      if (done) return { status: 'done', progress: 100, ports, msg: 'p_ports_done', params: { n: ports.length } };
      return { status: 'running', progress: pct, ports, msg: 'p_ports_progress', params: { done: Math.round(job.ports.length * p), total: job.ports.length } };
    }
    if (job.type === 'vulns') {
      if (done) return Object.assign({ status: 'done', progress: 100 }, job.result);
      return { status: 'running', progress: pct, msg: p < 0.5 ? 'p_vuln_scanning' : 'p_checking_vulns', params: { ip: job.ip } };
    }
    if (done) return { status: 'done', progress: 100, results: job.result, msg: 'p_done' };
    return { status: 'running', progress: pct, msg: 'p_running' };
  }

  function finish(job) {
    job.finished = true;
    db.scans++;
    if (job.type === 'discovery') {
      for (const lab of job.hosts) db.hosts[lab.ip] = hostRecord(lab, job.options);
    } else if (job.type === 'ports') {
      if (!db.hosts[job.ip]) db.hosts[job.ip] = Object.assign(hostRecord(job.lab || { ip: job.ip, mac: 'N/A', hostname: job.ip, vendor: 'Unknown', ttl: 64 }, {}), {});
      const open = {};
      for (const port of job.open) open[port] = { service: SERVICES[port] || 'unknown', banner: job.lab.ports[port] || '' };
      db.hosts[job.ip].open_ports = open;
    } else if (job.type === 'vulns') {
      const lab = byIp(job.ip);
      if (lab && (!db.hosts[job.ip] || !Object.keys(db.hosts[job.ip].open_ports).length)) {
        db.hosts[job.ip] = hostRecord(lab, {});
        const open = {};
        for (const port of Object.keys(lab.ports).map(Number).filter(p => COMMON.includes(p))) open[port] = { service: SERVICES[port] || 'unknown', banner: '' };
        db.hosts[job.ip].open_ports = open;
      }
      const vulns = lab ? vulnsFor(job.ip) : [];
      db.vulns = db.vulns.filter(v => v.host_ip !== job.ip).concat(vulns.map((v, i) => Object.assign({ id: Date.now() + i }, v)));
      const score = Math.min(100, vulns.reduce((a, v) => a + WEIGHT[v.severity], 0));
      if (db.hosts[job.ip]) db.hosts[job.ip].risk_score = score;
      job.result = { vulns, risk_score: score, msg: 'p_vulns_done', params: { n: vulns.length, score } };
    } else if (job.type === 'smb') {
      const lab = byIp(job.ip);
      const open = !!(lab && (445 in lab.ports || 139 in lab.ports));
      job.result = { port_open: open, tool: open ? 'smbclient (demo)' : null, users: [],
        shares: open ? (lab.shares || []).map(([name, type]) => ({ name, type })) : [] };
    } else if (job.type === 'dns') {
      job.result = job.domain === DOMAIN || job.domain.endsWith('.' + DOMAIN) ? {
        A: ['192.168.50.30'], MX: ['10 mail.' + DOMAIN + '.'], NS: ['ns1.' + DOMAIN + '.', 'ns2.' + DOMAIN + '.'],
        TXT: ['"v=spf1 mx -all"'], SOA: ['ns1.' + DOMAIN + '. admin.' + DOMAIN + '. 2026102001 3600 600 604800 300'],
        AXFR: ['ns1.' + DOMAIN + ': ' + (LAB.length + 3) + ' records'].concat(
          LAB.filter(h => h.hostname.endsWith(DOMAIN)).map(h => h.hostname + '. 300 IN A ' + h.ip)),
      } : { INFO: [document.documentElement.lang === 'en'
        ? 'In the demo only ' + DOMAIN + ' resolves. Download Nirvana LAN to query real domains.'
        : 'En la demo solo se resuelve ' + DOMAIN + '. Descarga Nirvana LAN para consultar dominios reales.'] };
    }
  }

  // ── Informes (mismo formato que el servidor, todo escapado) ──
  const e = v => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  function sortedHosts() { return Object.values(db.hosts).sort((a, b) => ipNum(a.ip) - ipNum(b.ip)); }
  function sortedVulns() { return db.vulns.slice().sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || ipNum(a.host_ip) - ipNum(b.host_ip)); }
  function reportHtml(lang) {
    const es = lang !== 'en';
    const T = es
      ? { title: 'Nirvana LAN — Informe de auditoría (DEMO)', gen: 'Generado', hosts: 'Equipos', findings: 'Hallazgos', ch: ['IP', 'Nombre', 'MAC', 'Fabricante', 'SO', 'Puertos', 'Riesgo'], cv: ['Equipo', 'Puerto', 'Servicio', 'Tipo', 'Severidad', 'Descripción', 'Recomendación'] }
      : { title: 'Nirvana LAN — Security audit report (DEMO)', gen: 'Generated', hosts: 'Hosts', findings: 'Findings', ch: ['IP', 'Hostname', 'MAC', 'Vendor', 'OS', 'Ports', 'Risk'], cv: ['Host', 'Port', 'Service', 'Type', 'Severity', 'Description', 'Recommendation'] };
    const vt = v => (es && window.VULN_ES && window.VULN_ES[v.vuln_type]) ? window.VULN_ES[v.vuln_type] : [v.description, v.recommendation];
    return '<!DOCTYPE html><html lang="' + (es ? 'es' : 'en') + '"><head><meta charset="UTF-8"><title>' + e(T.title) + '</title><style>' +
      "body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;padding:24px}h1{color:#00d4ff}h2{color:#a78bfa;border-bottom:1px solid #333}" +
      'table{width:100%;border-collapse:collapse;font-size:13px;margin:12px 0}th{background:#1e293b;padding:8px;text-align:left}td{border-bottom:1px solid #1e293b;padding:8px}' +
      '.b{padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px}.CRITICAL{background:#7f1d1d;color:#fca5a5}.HIGH{background:#7c2d12;color:#fdba74}.MEDIUM{background:#713f12;color:#fcd34d}.LOW{background:#1e3a5f;color:#93c5fd}.INFO{background:#1e293b;color:#94a3b8}' +
      '</style></head><body><h1>' + e(T.title) + '</h1><p>' + e(T.gen) + ': ' + e(new Date().toLocaleString()) + '</p>' +
      '<h2>' + e(T.hosts) + ' (' + sortedHosts().length + ')</h2><table><tr>' + T.ch.map(c => '<th>' + e(c) + '</th>').join('') + '</tr>' +
      sortedHosts().map(h => '<tr><td>' + e(h.ip) + '</td><td>' + e(h.hostname) + '</td><td>' + e(h.mac) + '</td><td>' + e(h.vendor) + '</td><td>' + e(h.os_guess) +
        '</td><td>' + e(Object.keys(h.open_ports).join(', ') || '-') + '</td><td>' + e(h.risk_score) + '</td></tr>').join('') +
      '</table><h2>' + e(T.findings) + ' (' + db.vulns.length + ')</h2><table><tr>' + T.cv.map(c => '<th>' + e(c) + '</th>').join('') + '</tr>' +
      sortedVulns().map(v => '<tr><td>' + e(v.host_ip) + '</td><td>' + e(v.port) + '</td><td>' + e(v.service) + '</td><td>' + e(v.vuln_type) +
        '</td><td><span class="b ' + e(v.severity) + '">' + e(v.severity) + '</span></td><td>' + e(vt(v)[0]) + '</td><td>' + e(vt(v)[1]) + '</td></tr>').join('') +
      '</table><p style="color:#64748b;text-align:center">Nirvana LAN · Un fantasma en el sistema · unfantasmaenelsistema.com</p></body></html>';
  }
  function reportTxt() {
    return ['NIRVANA LAN — DEMO REPORT', new Date().toISOString(), '', 'HOSTS']
      .concat(sortedHosts().map(h => '  ' + h.ip + '  ' + h.hostname + '  ' + h.mac + '  risk ' + h.risk_score))
      .concat(['', 'FINDINGS']).concat(sortedVulns().map(v => '  [' + v.severity + '] ' + v.host_ip + ':' + v.port + ' ' + v.vuln_type))
      .join('\n');
  }

  // ── Enrutador de la API ──────────────────────────────────
  function stats() {
    const hosts = Object.values(db.hosts);
    const count = sev => db.vulns.filter(v => v.severity === sev).length;
    const portCount = {};
    hosts.forEach(h => Object.keys(h.open_ports).forEach(p => { portCount[p] = (portCount[p] || 0) + 1; }));
    const top = Object.entries(portCount).sort((a, b) => b[1] - a[1] || a[0] - b[0]).slice(0, 10)
      .map(([p, c]) => ({ port: +p, service: SERVICES[p] || 'unknown', count: c }));
    return { total_hosts: hosts.length, up_hosts: hosts.length, total_vulns: db.vulns.length, critical: count('CRITICAL'),
      high: count('HIGH'), medium: count('MEDIUM'), low: count('LOW'), scans: db.scans, top_ports: top };
  }

  function route(method, path, query, body) {
    if (path === 'network-info') return { networks: [{ interface: 'Ethernet (demo)', ip: MY_IP, netmask: '255.255.255.0', network: LAB_NET, cidr: '24' }], hostname: 'ghost-pc', suggested: LAB_NET, platform: 'demo', demo: true };
    if (path === 'stats') return stats();
    if (path === 'hosts' && method === 'GET') return sortedHosts();
    if (path === 'hosts/clear') { db.hosts = {}; db.vulns = []; db.scans = 0; return { ok: true }; }
    let m = path.match(/^hosts\/([^/]+)\/notes$/);
    if (m) { const h = db.hosts[decodeURIComponent(m[1])]; if (h) h.notes = String(body.notes || '').slice(0, 4000); return { ok: true }; }
    m = path.match(/^hosts\/([^/]+)$/);
    if (m) {
      const h = db.hosts[decodeURIComponent(m[1])];
      if (!h) return [404, { error: 'err_host_not_found' }];
      return Object.assign({}, h, { vulnerabilities: sortedVulns().filter(v => v.host_ip === h.ip) });
    }
    if (path === 'vulnerabilities') return sortedVulns();
    if (path === 'scan/start') return { scan_id: launch(body.type, body.target, body.options, body.port_range) };
    m = path.match(/^scan\/status\/(\w+)$/);
    if (m) return status(m[1]);
    if (path === 'scheduled' && method === 'GET') return db.tasks;
    if (path === 'scheduled' && method === 'POST') {
      if (!String(body.name || '').trim()) throw bad('err_missing_fields');
      const target = body.scan_type === 'discovery' ? parseNet(body.target).str : parseIp(body.target);
      const delta = { hourly: 3600e3, daily: 864e5, weekly: 6048e5 }[body.schedule];
      db.tasks.push({ id: ++db.taskSeq, name: String(body.name).slice(0, 80), scan_type: body.scan_type, target, schedule: body.schedule,
        last_run: null, next_run: delta ? new Date(Date.now() + delta).toISOString() : null, enabled: 1 });
      return { ok: true };
    }
    m = path.match(/^scheduled\/(\d+)\/run$/);
    if (m) {
      const task = db.tasks.find(x => x.id === +m[1]);
      if (!task) return [404, { error: 'err_task_not_found' }];
      task.last_run = now();
      return { scan_id: launch(task.scan_type, task.target, { os_detect: true }, 'common'), scan_type: task.scan_type };
    }
    m = path.match(/^scheduled\/(\d+)$/);
    if (m && method === 'DELETE') { db.tasks = db.tasks.filter(x => x.id !== +m[1]); return { ok: true }; }
    if (path === 'report/html') return ['html', reportHtml(query.get('lang'))];
    if (path === 'report/txt') return ['txt', reportTxt()];
    return [404, { error: 'not_found' }];
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const url = new URL(typeof input === 'string' ? input : input.url, location.href);
    const base = new URL('api/', location.href).pathname;
    if (!url.pathname.startsWith(base)) return realFetch(input, init);
    const path = url.pathname.slice(base.length);
    const method = (init && init.method) || 'GET';
    let body = {};
    try { body = init && init.body ? JSON.parse(init.body) : {}; } catch (err) { body = {}; }
    await new Promise(r => setTimeout(r, 60));
    let out;
    try {
      out = route(method, path, url.searchParams, body);
      persist();
    } catch (err) {
      out = [400, { error: err.key || 'err_generic', params: err.params || { error: String(err.message) } }];
    }
    if (Array.isArray(out) && (out[0] === 'html' || out[0] === 'txt')) {
      return new Response(out[1], { status: 200, headers: { 'Content-Type': out[0] === 'html' ? 'text/html' : 'text/plain' } });
    }
    const [code, payload] = Array.isArray(out) && typeof out[0] === 'number' ? out : [200, out];
    return new Response(JSON.stringify(payload), { status: code, headers: { 'Content-Type': 'application/json' } });
  };

  // ── Aviso de demo ────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    const lang = document.documentElement.lang === 'en' ? 'en' : 'es';
    const div = document.createElement('div');
    div.className = 'demo-banner';
    div.id = 'demoBanner';
    div.innerHTML = '<b>DEMO</b><span data-i18n="demo_banner"></span>' +
      '<a href="https://github.com/unfantasmaenelsistema/NirvanaLan#instalación" target="_blank" rel="noopener noreferrer" data-i18n="demo_download"></a>';
    const legal = document.getElementById('legalNote');
    legal.parentNode.insertBefore(div, legal);
    div.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = window.I18N[lang][el.dataset.i18n]; });
  });
})();
