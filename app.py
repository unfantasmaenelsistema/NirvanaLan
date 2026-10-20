#!/usr/bin/env python3
"""
Nirvana LAN — herramienta de auditoría de red local con interfaz web.
https://github.com/unfantasmaenelsistema/NirvanaLan

Úsala solo en redes propias o con autorización por escrito.
"""

import os
import sys
import json
import time
import argparse
import threading
import webbrowser
import sqlite3
import secrets
import html
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, send_file, abort
import socket
import subprocess
import platform
import re
import ipaddress
import concurrent.futures
import psutil
import io

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024

IS_WINDOWS = platform.system().lower() == 'windows'
MAX_DISCOVERY_HOSTS = 1024          # /22 como máximo
MAX_PORTS_PER_SCAN = 65535

# ─────────────────────────────────────────────
# BASE DE DATOS
# ─────────────────────────────────────────────
DB_PATH = os.path.join(BASE_DIR, 'db', 'nirvana.db')


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE, mac TEXT, hostname TEXT,
        vendor TEXT, os_guess TEXT, status TEXT,
        open_ports TEXT, services TEXT, last_seen TEXT,
        risk_score INTEGER DEFAULT 0, notes TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT, target TEXT, started_at TEXT,
        finished_at TEXT, status TEXT, results TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_ip TEXT, port INTEGER, service TEXT,
        vuln_type TEXT, severity TEXT, description TEXT,
        recommendation TEXT, found_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scheduled_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, scan_type TEXT, target TEXT,
        schedule TEXT, last_run TEXT, next_run TEXT,
        enabled INTEGER DEFAULT 1
    )''')
    conn.commit()
    conn.close()


def db_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────
# VALIDACIÓN DE ENTRADAS
# Todo lo que acaba en un comando externo (ping, dig, smbclient…) pasa por
# aquí: así un objetivo como "-f/etc/passwd" nunca llega a un programa.
# ─────────────────────────────────────────────
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?!-)([A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9-]{1,63}\.?$')


class BadInput(ValueError):
    def __init__(self, key, **params):
        super().__init__(key)
        self.key = key
        self.params = params


def parse_ip(value):
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except Exception:
        raise BadInput('err_bad_ip', value=str(value)[:60])


def parse_network(value):
    try:
        net = ipaddress.IPv4Network(str(value).strip(), strict=False)
    except Exception:
        raise BadInput('err_bad_network', value=str(value)[:60])
    if net.num_addresses > MAX_DISCOVERY_HOSTS + 2:
        raise BadInput('err_range_too_big', hosts=net.num_addresses - 2, max=MAX_DISCOVERY_HOSTS)
    return net


def parse_domain(value):
    v = str(value).strip()
    if not DOMAIN_RE.match(v):
        raise BadInput('err_bad_domain', value=v[:60])
    return v.rstrip('.')


def parse_ports(spec):
    """'common' | 'top1000' | '1-1024' | 'full' | '80,443,8000-8100'"""
    spec = str(spec or 'common').strip().lower()
    if spec == 'common':
        return sorted(COMMON_PORTS)
    if spec == 'top1000':
        return list(range(1, 1001))
    if spec == 'full':
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r'(\d{1,5})(?:-(\d{1,5}))?', part)
        if not m:
            raise BadInput('err_bad_ports', value=part[:30])
        a = int(m.group(1))
        b = int(m.group(2) or a)
        if not (1 <= a <= 65535 and 1 <= b <= 65535 and a <= b):
            raise BadInput('err_bad_ports', value=part[:30])
        ports.update(range(a, b + 1))
    if not ports:
        raise BadInput('err_bad_ports', value=spec[:30])
    return sorted(ports)


# ─────────────────────────────────────────────
# UTILIDADES DE RED
# ─────────────────────────────────────────────

def get_local_networks():
    """Interfaces locales con su red IPv4 (psutil y, si falla, gethostbyname)."""
    networks = []
    seen = set()
    try:
        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            st = stats.get(iface)
            if st and not st.isup:
                continue
            for addr in addrs:
                if addr.family != socket.AF_INET:
                    continue
                ip = addr.address
                if not ip or ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                netmask = addr.netmask if addr.netmask and addr.netmask != '0.0.0.0' else '255.255.255.0'
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                except Exception:
                    continue
                if str(net) in seen or net.prefixlen > 30:
                    continue
                seen.add(str(net))
                networks.append({'interface': iface, 'ip': ip, 'netmask': str(net.netmask),
                                 'network': str(net), 'cidr': str(net.prefixlen)})
    except Exception:
        pass

    if not networks:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            if local_ip and not local_ip.startswith('127.'):
                net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                networks.append({'interface': 'default', 'ip': local_ip, 'netmask': '255.255.255.0',
                                 'network': str(net), 'cidr': '24'})
        except Exception:
            pass

    def priority(n):
        ip = n['ip']
        score = 0 if ip.startswith('192.168.') else 1 if ip.startswith('10.') else 2 if ip.startswith('172.') else 3
        return (score, int(n['cidr']))

    networks.sort(key=priority)
    return networks


def ping_cmd(ip, timeout_s=1, count=1):
    if IS_WINDOWS:
        return ['ping', '-n', str(count), '-w', str(int(timeout_s * 1000)), ip]
    return ['ping', '-c', str(count), '-W', str(max(1, int(timeout_s))), ip]


def tcp_alive(ip, timeout=0.8):
    """Host vivo si acepta o rechaza activamente una conexión TCP en puertos típicos."""
    for port in (80, 443, 22, 445, 139, 135, 3389, 8080, 21, 23, 53, 8443):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout * 0.4)
                r = s.connect_ex((ip, port))
            # 0 = abierto; 10061/111 = conexión rechazada (el host existe)
            if r in (0, 111, 10061):
                return True
        except Exception:
            pass
    return False


def arp_table():
    """Lee la caché ARP del sistema: {ip: mac}."""
    hosts = {}
    try:
        if IS_WINDOWS:
            out = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.fullmatch(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    mac = parts[1].replace('-', ':').lower()
                    if re.fullmatch(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
                        hosts[parts[0]] = mac
        else:
            try:
                with open('/proc/net/arp') as f:
                    for line in f.readlines()[1:]:
                        p = line.split()
                        if len(p) >= 4 and p[2] != '0x0':
                            hosts[p[0]] = p[3].lower()
            except OSError:
                out = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=8).stdout
                for m in re.finditer(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})', out, re.I):
                    hosts[m.group(1)] = m.group(2).lower()
    except Exception:
        pass
    return {ip: mac for ip, mac in hosts.items()
            if mac not in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')}


def arp_scan(network):
    """Entradas ARP que pertenecen a la red pedida (antes devolvía también las de otras interfaces)."""
    net = ipaddress.IPv4Network(network, strict=False)
    out = {}
    for ip, mac in arp_table().items():
        try:
            addr = ipaddress.IPv4Address(ip)
        except Exception:
            continue
        if addr in net and addr != net.network_address and addr != net.broadcast_address:
            out[ip] = mac
    return out


OUI_DB = {
    '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:05:69': 'VMware', '08:00:27': 'VirtualBox',
    '0a:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM', '00:15:5d': 'Hyper-V', '00:1c:42': 'Parallels',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi', 'd8:3a:dd': 'Raspberry Pi',
    '00:1a:11': 'Google', 'f4:f5:d8': 'Google', '54:60:09': 'Google',
    'ac:bc:32': 'Apple', '00:03:93': 'Apple', '00:05:02': 'Apple', '3c:22:fb': 'Apple',
    '8c:85:90': 'Apple', 'f0:18:98': 'Apple', '28:cd:c1': 'Apple',
    '00:1b:21': 'Intel', '00:21:6a': 'Intel', '8c:8d:28': 'Intel',
    '00:1d:60': 'Cisco', '00:1e:13': 'Cisco', '00:1f:ca': 'Cisco',
    '78:4f:43': 'Dell', 'f8:b1:56': 'Dell', '00:14:22': 'Dell', '00:21:9b': 'Dell',
    '00:50:ba': 'D-Link', '00:1c:f0': 'D-Link', '14:d6:4d': 'D-Link',
    'c8:3a:35': 'Tenda', 'f4:ec:38': 'TP-Link', '50:c7:bf': 'TP-Link',
    '00:90:f5': 'ASUS', '00:1f:c6': 'ASUS', '04:d9:f5': 'ASUS',
    '00:23:ae': 'Dell', 'a0:21:b7': 'Netgear', '20:4e:7f': 'Netgear',
    '00:25:9c': 'Cisco Linksys', 'c0:c1:c0': 'Cisco Linksys', '00:11:32': 'Synology',
    '3c:52:82': 'HP', '00:1b:78': 'HP', '64:51:06': 'HP',
}


def get_mac_vendor(mac):
    if not mac or len(mac) < 8:
        return 'Unknown'
    prefix = mac[:8].lower()
    if int(prefix[:2], 16) & 0x02:
        return 'Locally administered'
    return OUI_DB.get(prefix, 'Unknown')


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0][:120]
    except Exception:
        return ip


def scan_port(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False


HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000, 9000, 9090, 9200, 10000}


def get_service_banner(ip, port, timeout=2):
    """Banner del servicio: primero escucha (SSH, FTP, SMTP…); en puertos web pide un HEAD."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            data = b''
            if port not in HTTP_PORTS:
                try:
                    data = sock.recv(256)
                except socket.timeout:
                    data = b''
            if not data:
                sock.sendall(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                data = sock.recv(512)
        text = data.decode('utf-8', errors='replace')
        if text.startswith('HTTP/'):
            server = re.search(r'^Server:\s*(.+)$', text, re.I | re.M)
            first = text.splitlines()[0]
            text = first + (' | Server: ' + server.group(1).strip() if server else '')
        text = ''.join(ch if ch.isprintable() else ' ' for ch in text)
        return re.sub(r'\s+', ' ', text).strip()[:200]
    except Exception:
        return ''


COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    69: 'TFTP', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 119: 'NNTP', 135: 'MSRPC',
    139: 'NetBIOS/SMB', 143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 515: 'LPD', 548: 'AFP', 554: 'RTSP', 587: 'SMTP', 631: 'IPP', 636: 'LDAPS',
    873: 'rsync', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL',
    1521: 'Oracle', 1723: 'PPTP', 1883: 'MQTT', 2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel SSL',
    2222: 'SSH alt', 3000: 'HTTP dev', 3306: 'MySQL', 3389: 'RDP', 3690: 'SVN', 4443: 'HTTPS alt',
    5000: 'HTTP dev', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM HTTP', 5986: 'WinRM HTTPS',
    6379: 'Redis', 7070: 'RTSP', 8000: 'HTTP alt', 8080: 'HTTP proxy', 8443: 'HTTPS alt',
    8888: 'HTTP alt', 9000: 'HTTP alt', 9090: 'Prometheus', 9100: 'JetDirect', 9200: 'Elasticsearch',
    10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB',
}


def os_fingerprint(ip):
    """Pista de sistema operativo por el TTL de la respuesta ICMP."""
    try:
        r = subprocess.run(ping_cmd(ip, 1), capture_output=True, text=True, timeout=4)
        m = re.search(r'ttl[=:\s]+(\d+)', r.stdout + r.stderr, re.I)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:
                return 'Linux/Unix/macOS (TTL≤64)'
            if ttl <= 128:
                return 'Windows (TTL≤128)'
            return 'Network device (TTL≤255)'
    except Exception:
        pass
    return 'Unknown'


# ─────────────────────────────────────────────
# DNS
# ─────────────────────────────────────────────

def dns_enum(domain):
    """Registros A, AAAA, MX, NS, TXT, SOA y CNAME e intento de transferencia de zona (AXFR con dig)."""
    if _which('dig'):
        results = _dns_dig(domain)
    elif IS_WINDOWS:
        results = _dns_powershell(domain)
    else:
        results = {}

    if _which('dig') and results.get('NS'):
        axfr = []
        for ns in results['NS'][:3]:
            ns = ns.rstrip('.')
            if not DOMAIN_RE.match(ns):
                continue
            try:
                out = subprocess.run(['dig', '@' + ns, '-t', 'AXFR', '-q', domain],
                                     capture_output=True, text=True, timeout=10).stdout
                records = [l for l in out.splitlines() if l.strip() and not l.startswith(';')]
                if records and 'Transfer failed' not in out:
                    axfr.append(f"{ns}: {len(records)} records")
                    axfr.extend(records[:40])
            except Exception:
                pass
        if axfr:
            results['AXFR'] = axfr
    return results


def _which(cmd):
    from shutil import which
    return which(cmd) is not None


def _dns_dig(domain):
    results = {}
    for rtype in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME'):
        try:
            out = subprocess.run(['dig', '+short', '-t', rtype, '-q', domain],
                                 capture_output=True, text=True, timeout=6).stdout
            lines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(';')]
            if lines:
                results[rtype] = lines[:30]
        except Exception:
            pass
    return results


# Tipos numéricos que devuelve Resolve-DnsName en JSON
_PS_TYPES = {1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 16: 'TXT', 6: 'SOA', 5: 'CNAME'}


def _dns_powershell(domain):
    """Windows sin dig: Resolve-DnsName en JSON (independiente del idioma del sistema).
    El dominio ya ha pasado DOMAIN_RE, así que no puede romper las comillas."""
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$r=foreach($t in 'A','AAAA','MX','NS','TXT','SOA','CNAME'){"
        f"Resolve-DnsName -Name '{domain}' -Type $t -DnsOnly -QuickTimeout |"
        " Where-Object { $_.Section -eq 1 -or $_.Section -eq 'Answer' } };"
        "$r | Select-Object Name,Type,IPAddress,NameHost,NameExchange,Preference,Strings,"
        "PrimaryServer,NameAdministrator,SerialNumber | ConvertTo-Json -Compress -Depth 3")
    try:
        out = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                             capture_output=True, text=True, timeout=40).stdout.strip()
        data = json.loads(out) if out else []
    except Exception:
        return {}
    if isinstance(data, dict):
        data = [data]
    results = {}
    for rec in data:
        rtype = _PS_TYPES.get(rec.get('Type')) if isinstance(rec.get('Type'), int) else rec.get('Type')
        if rtype == 'A' or rtype == 'AAAA':
            val = rec.get('IPAddress')
        elif rtype == 'MX':
            val = f"{rec.get('Preference')} {rec.get('NameExchange')}"
        elif rtype in ('NS', 'CNAME'):
            val = rec.get('NameHost')
        elif rtype == 'TXT':
            strings = rec.get('Strings') or []
            val = ' '.join(strings if isinstance(strings, list) else [strings])
        elif rtype == 'SOA':
            val = f"{rec.get('PrimaryServer')} {rec.get('NameAdministrator')} {rec.get('SerialNumber')}"
        else:
            continue
        if val and val not in results.setdefault(rtype, []):
            results[rtype].append(str(val)[:300])
    return {k: v[:30] for k, v in results.items() if v}


# ─────────────────────────────────────────────
# SMB
# ─────────────────────────────────────────────

def smb_enum(ip):
    results = {'shares': [], 'users': [], 'port_open': False, 'tool': None}
    if not (scan_port(ip, 445) or scan_port(ip, 139)):
        return results
    results['port_open'] = True

    if IS_WINDOWS:
        results['tool'] = 'net view'
        try:
            out = subprocess.run(['net', 'view', '\\\\' + ip, '/all'], capture_output=True, text=True, timeout=12).stdout
            for line in out.splitlines():
                m = re.match(r'^(\S+)\s+(Disk|Disco|IPC|Print|Impresora)\b', line, re.I)
                if m:
                    results['shares'].append({'name': m.group(1)[:80], 'type': m.group(2)})
        except Exception:
            pass
        return results

    if _which('smbclient'):
        results['tool'] = 'smbclient'
        try:
            proc = subprocess.run(['smbclient', '-L', '//' + ip, '-N'], capture_output=True, text=True, timeout=12)
            for m in re.finditer(r'^\s+(\S+)\s+(Disk|IPC|Printer)', proc.stdout + proc.stderr, re.M | re.I):
                results['shares'].append({'name': m.group(1)[:80], 'type': m.group(2)})
        except Exception:
            pass
    if _which('rpcclient'):
        try:
            proc = subprocess.run(['rpcclient', '-U', '%', '-N', '-c', 'enumdomusers', ip],
                                  capture_output=True, text=True, timeout=10)
            results['users'] = [u[:80] for u in re.findall(r'user:\[([^\]]+)\]', proc.stdout)][:200]
        except Exception:
            pass
    return results


# ─────────────────────────────────────────────
# SNMP (UDP 161) — community "public"
# ─────────────────────────────────────────────

def _ber_len(n):
    return bytes([n]) if n < 0x80 else bytes([0x81, n])


def _tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def snmp_public(ip, community=b'public', timeout=1.5):
    """Envía un GetRequest SNMPv1 de sysDescr.0. Si contesta, la comunidad es legible."""
    oid = bytes([0x2b, 6, 1, 2, 1, 1, 1, 0])                 # 1.3.6.1.2.1.1.1.0
    varbind = _tlv(0x30, _tlv(0x06, oid) + b'\x05\x00')
    pdu = _tlv(0xa0, _tlv(0x02, b'\x01\x02\x03\x04') + _tlv(0x02, b'\x00') + _tlv(0x02, b'\x00') + _tlv(0x30, varbind))
    msg = _tlv(0x30, _tlv(0x02, b'\x00') + _tlv(0x04, community) + pdu)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(msg, (ip, 161))
            data, _ = s.recvfrom(2048)
        if data[:1] != b'\x30' or b'\xa2' not in data:
            return None
        m = re.search(rb'\x04[\x01-\x7f]([\x20-\x7e]{3,})', data[data.find(b'\x2b\x06\x01\x02\x01\x01\x01\x00'):])
        return (m.group(1).decode('ascii', 'replace') if m else 'SNMP')[:120]
    except Exception:
        return None


# ─────────────────────────────────────────────
# VULNERABILIDADES
# Los textos van en inglés en la base de datos; la interfaz los traduce
# por su identificador (vuln_type).
# ─────────────────────────────────────────────

VULN_CHECKS = [
    {'id': 'TELNET_OPEN', 'port': 23, 'service': 'Telnet', 'severity': 'CRITICAL',
     'description': 'Telnet transmits data in plaintext, including credentials. Highly vulnerable to MITM attacks.',
     'recommendation': 'Disable Telnet immediately. Use SSH instead.'},
    {'id': 'FTP_OPEN', 'port': 21, 'service': 'FTP', 'severity': 'HIGH',
     'description': 'FTP transmits credentials and data unencrypted.',
     'recommendation': 'Use SFTP or FTPS. Disable anonymous access.'},
    {'id': 'SMB_OPEN', 'port': 445, 'service': 'SMB', 'severity': 'HIGH',
     'description': 'SMB port exposed. Vulnerable to EternalBlue (MS17-010) and related exploits if unpatched.',
     'recommendation': 'Ensure system is fully patched. Enable SMB signing. Block if not needed.'},
    {'id': 'RDP_OPEN', 'port': 3389, 'service': 'RDP', 'severity': 'HIGH',
     'description': 'RDP exposed to network. Susceptible to BlueKeep (CVE-2019-0708) and brute force.',
     'recommendation': 'Restrict access via VPN. Enable NLA. Keep patched.'},
    {'id': 'MSSQL_OPEN', 'port': 1433, 'service': 'MSSQL', 'severity': 'HIGH',
     'description': 'MSSQL database port exposed. Risk of credential attacks.',
     'recommendation': 'Restrict access. Disable SA account. Use strong passwords.'},
    {'id': 'MYSQL_OPEN', 'port': 3306, 'service': 'MySQL', 'severity': 'HIGH',
     'description': 'MySQL database exposed to network. Risk of unauthorized access.',
     'recommendation': 'Bind to localhost only. Use strong credentials.'},
    {'id': 'MONGODB_OPEN', 'port': 27017, 'service': 'MongoDB', 'severity': 'CRITICAL',
     'description': 'MongoDB may be running without authentication.',
     'recommendation': 'Enable authentication. Bind to specific interfaces only.'},
    {'id': 'REDIS_OPEN', 'port': 6379, 'service': 'Redis', 'severity': 'CRITICAL',
     'description': 'Redis often has no authentication by default. Full data access risk.',
     'recommendation': 'Enable requirepass/ACLs. Restrict network access.'},
    {'id': 'MEMCACHED_OPEN', 'port': 11211, 'service': 'Memcached', 'severity': 'HIGH',
     'description': 'Memcached has no authentication and can leak cached data or be abused for amplification.',
     'recommendation': 'Bind to localhost and disable UDP.'},
    {'id': 'VNC_OPEN', 'port': 5900, 'service': 'VNC', 'severity': 'HIGH',
     'description': 'VNC exposes desktop remotely. Often weakly authenticated.',
     'recommendation': 'Use strong password. Tunnel through SSH. Restrict access.'},
    {'id': 'ELASTICSEARCH_OPEN', 'port': 9200, 'service': 'Elasticsearch', 'severity': 'CRITICAL',
     'description': 'Elasticsearch may be accessible without authentication, exposing all indexed data.',
     'recommendation': 'Enable security features. Restrict to localhost.'},
    {'id': 'HTTP_OPEN', 'port': 80, 'service': 'HTTP', 'severity': 'LOW',
     'description': 'HTTP transmits data unencrypted.',
     'recommendation': 'Migrate to HTTPS. Implement HSTS.'},
    {'id': 'SSH_OPEN', 'port': 22, 'service': 'SSH', 'severity': 'INFO',
     'description': 'SSH service detected. Verify key-based auth and disable root login.',
     'recommendation': 'Use key-based auth. Disable password auth.'},
]

BANNER_CHECKS = [
    (r'Apache/2\.[0-2]\.', 'OUTDATED_APACHE', 'HIGH', 'Outdated Apache version detected.', 'Update to the latest Apache 2.4.x.'),
    (r'OpenSSH_[2-6]\.', 'OUTDATED_OPENSSH', 'HIGH', 'Old OpenSSH version detected.', 'Update OpenSSH to the latest version.'),
    (r'Microsoft-IIS/[5-7]\.', 'OUTDATED_IIS', 'HIGH', 'Outdated IIS detected.', 'Update IIS or migrate to a supported Windows Server.'),
    (r'vsftpd 2\.3\.4', 'VSFTPD_BACKDOOR', 'CRITICAL', 'vsftpd 2.3.4 (backdoored release, CVE-2011-2523).', 'Replace vsftpd immediately.'),
    (r'vsftpd 2\.[0-3]', 'OUTDATED_VSFTPD', 'MEDIUM', 'Old vsftpd version.', 'Update vsftpd.'),
    (r'MiniServ', 'WEBMIN_DETECTED', 'MEDIUM', 'Webmin detected. Check for known vulnerabilities.', 'Update Webmin regularly and restrict access.'),
]


def check_vulns(ip, open_ports, banners=None):
    """open_ports: {port: service}; banners: {port: banner} si ya se capturaron."""
    now = datetime.now().isoformat()
    vulns = []
    for c in VULN_CHECKS:
        if c['port'] in open_ports:
            vulns.append({'host_ip': ip, 'port': c['port'], 'service': c['service'], 'vuln_type': c['id'],
                          'severity': c['severity'], 'description': c['description'],
                          'recommendation': c['recommendation'], 'found_at': now})

    banners = dict(banners or {})
    for port in open_ports:
        if port not in banners:
            banners[port] = get_service_banner(ip, port)
    for port, banner in banners.items():
        if not banner:
            continue
        for pattern, vid, sev, desc, rec in BANNER_CHECKS:
            if re.search(pattern, banner, re.I):
                vulns.append({'host_ip': ip, 'port': port, 'service': open_ports.get(port, 'unknown'),
                              'vuln_type': vid, 'severity': sev,
                              'description': f"{desc} Banner: {banner[:100]}",
                              'recommendation': rec, 'found_at': now})
                break

    sysdescr = snmp_public(ip)
    if sysdescr:
        vulns.append({'host_ip': ip, 'port': 161, 'service': 'SNMP', 'vuln_type': 'SNMP_PUBLIC',
                      'severity': 'HIGH',
                      'description': f'SNMP answers with the default community "public" (sysDescr: {sysdescr}).',
                      'recommendation': 'Change the community string or move to SNMPv3 with authentication.',
                      'found_at': now})
    return vulns


SEVERITY_WEIGHT = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5, 'INFO': 1}
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


def risk_score(vulns):
    return min(100, sum(SEVERITY_WEIGHT.get(v['severity'], 0) for v in vulns))


# ─────────────────────────────────────────────
# GESTOR DE ESCANEOS
# Los mensajes de progreso van como clave + parámetros para que la
# interfaz los muestre en español o en inglés.
# ─────────────────────────────────────────────

scan_progress = {}
progress_lock = threading.Lock()


def set_progress(scan_id, **kw):
    with progress_lock:
        scan_progress.setdefault(scan_id, {}).update(kw)


def msg(key, **params):
    return {'msg': key, 'params': params}


def run_discovery_scan(scan_id, network, options):
    started_at = datetime.now().isoformat()
    set_progress(scan_id, status='running', progress=0, hosts=[], started_at=started_at, **msg('p_starting'))
    try:
        net = parse_network(network)
        hosts_list = [str(h) for h in net.hosts()]
        total = len(hosts_list)
        if not total:
            set_progress(scan_id, status='error', **msg('err_empty_range'))
            return

        # 1) Sondas ICMP para llenar la caché ARP
        set_progress(scan_id, **msg('p_probing', n=total))
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
            futs = [ex.submit(subprocess.run, ping_cmd(ip, 0.5), capture_output=True, timeout=3) for ip in hosts_list]
            done = 0
            for f in concurrent.futures.as_completed(futs):
                done += 1
                if done % 16 == 0:
                    set_progress(scan_id, progress=int(done / total * 40))
                try:
                    f.result()
                except Exception:
                    pass

        # 2) Caché ARP filtrada a la red objetivo
        set_progress(scan_id, progress=40, **msg('p_reading_arp'))
        arp_hosts = arp_scan(str(net))
        set_progress(scan_id, **msg('p_arp_found', n=len(arp_hosts)))

        found = []
        lock = threading.Lock()
        local_ips = {n['ip'] for n in get_local_networks()}

        def check_host(ip):
            alive = ip in arp_hosts or ip in local_ips or tcp_alive(ip)
            if not alive:
                return None
            mac = arp_hosts.get(ip, '')
            host = {
                'ip': ip,
                'mac': mac or 'N/A',
                'hostname': resolve_hostname(ip) if options.get('resolve_hostnames', True) else ip,
                'vendor': get_mac_vendor(mac) if options.get('vendor_lookup', True) else 'Unknown',
                'os_guess': os_fingerprint(ip) if options.get('os_detect') else 'Unknown',
                'status': 'up',
                'last_seen': datetime.now().isoformat(),
            }
            save_host(host)
            with lock:
                found.append(host)
            with progress_lock:
                scan_progress[scan_id]['hosts'].append(host)
            return host

        with concurrent.futures.ThreadPoolExecutor(max_workers=96) as ex:
            futures = [ex.submit(check_host, ip) for ip in hosts_list]
            done = 0
            for f in concurrent.futures.as_completed(futures):
                done += 1
                try:
                    f.result()
                except Exception:
                    pass
                if done % 8 == 0 or done == total:
                    set_progress(scan_id, progress=40 + int(done / total * 60),
                                 **msg('p_scanned', done=done, total=total, found=len(found)))

        conn = db_conn()
        conn.execute('INSERT INTO scans (scan_type, target, started_at, finished_at, status, results) VALUES (?,?,?,?,?,?)',
                     ('discovery', str(net), started_at, datetime.now().isoformat(), 'completed', json.dumps(found)))
        conn.commit()
        conn.close()
        set_progress(scan_id, status='done', progress=100, **msg('p_discovery_done', n=len(found)))
    except BadInput as e:
        set_progress(scan_id, status='error', **msg(e.key, **e.params))
    except Exception as e:
        set_progress(scan_id, status='error', **msg('err_generic', error=str(e)[:200]))


def save_host(host):
    """Inserta o actualiza sin borrar puertos, riesgo ni notas ya guardados."""
    conn = db_conn()
    conn.execute('''INSERT INTO hosts (ip, mac, hostname, vendor, os_guess, status, last_seen)
                    VALUES (?,?,?,?,?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET
                      mac=CASE WHEN excluded.mac != 'N/A' THEN excluded.mac ELSE hosts.mac END,
                      hostname=excluded.hostname, vendor=excluded.vendor,
                      os_guess=CASE WHEN excluded.os_guess != 'Unknown' THEN excluded.os_guess ELSE hosts.os_guess END,
                      status=excluded.status, last_seen=excluded.last_seen''',
                 (host['ip'], host['mac'], host['hostname'], host['vendor'], host['os_guess'], host['status'], host['last_seen']))
    conn.commit()
    conn.close()


def ensure_host(ip):
    conn = db_conn()
    conn.execute("INSERT OR IGNORE INTO hosts (ip, mac, hostname, vendor, os_guess, status, last_seen) VALUES (?,?,?,?,?,?,?)",
                 (ip, 'N/A', ip, 'Unknown', 'Unknown', 'up', datetime.now().isoformat()))
    conn.commit()
    conn.close()


def run_port_scan(scan_id, ip, port_spec='common'):
    set_progress(scan_id, status='running', progress=0, ports=[], **msg('p_port_scanning', ip=ip))
    try:
        ip = parse_ip(ip)
        ports = parse_ports(port_spec)
        total = len(ports)
        counter = {'done': 0}
        clock = threading.Lock()

        def check_port(port):
            is_open = scan_port(ip, port, timeout=0.8)
            with clock:
                counter['done'] += 1
                d = counter['done']
            if d % 64 == 0 or d == total:
                set_progress(scan_id, progress=int(d / total * 100), **msg('p_ports_progress', done=d, total=total))
            if not is_open:
                return None
            return port, COMMON_PORTS.get(port, 'unknown'), get_service_banner(ip, port)

        open_ports = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
            for f in concurrent.futures.as_completed([ex.submit(check_port, p) for p in ports]):
                r = f.result()
                if r:
                    port, service, banner = r
                    open_ports[port] = {'service': service, 'banner': banner}
                    with progress_lock:
                        scan_progress[scan_id]['ports'].append({'port': port, 'service': service, 'banner': banner})

        ensure_host(ip)
        conn = db_conn()
        conn.execute('UPDATE hosts SET open_ports=?, last_seen=? WHERE ip=?',
                     (json.dumps({str(k): v for k, v in sorted(open_ports.items())}), datetime.now().isoformat(), ip))
        conn.execute('INSERT INTO scans (scan_type, target, started_at, finished_at, status, results) VALUES (?,?,?,?,?,?)',
                     ('ports', ip, scan_progress[scan_id].get('started_at', ''), datetime.now().isoformat(), 'completed',
                      json.dumps(sorted(open_ports))))
        conn.commit()
        conn.close()
        set_progress(scan_id, status='done', progress=100, open_ports=open_ports, **msg('p_ports_done', n=len(open_ports)))
    except BadInput as e:
        set_progress(scan_id, status='error', **msg(e.key, **e.params))
    except Exception as e:
        set_progress(scan_id, status='error', **msg('err_generic', error=str(e)[:200]))


def run_vuln_scan(scan_id, ip):
    set_progress(scan_id, status='running', progress=0, **msg('p_vuln_scanning', ip=ip))
    try:
        ip = parse_ip(ip)
        conn = db_conn()
        row = conn.execute('SELECT open_ports FROM hosts WHERE ip=?', (ip,)).fetchone()
        conn.close()
        banners = {}
        if row and row['open_ports']:
            data = json.loads(row['open_ports'])
            open_ports = {int(k): (v['service'] if isinstance(v, dict) else v) for k, v in data.items()}
            banners = {int(k): v.get('banner', '') for k, v in data.items() if isinstance(v, dict)}
        else:
            set_progress(scan_id, progress=10, **msg('p_quick_ports'))
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
                res = dict(zip(sorted(COMMON_PORTS), ex.map(lambda p: scan_port(ip, p, 0.8), sorted(COMMON_PORTS))))
            open_ports = {p: COMMON_PORTS[p] for p, ok in res.items() if ok}
            ensure_host(ip)
            conn = db_conn()
            conn.execute('UPDATE hosts SET open_ports=? WHERE ip=?',
                         (json.dumps({str(p): {'service': s, 'banner': ''} for p, s in open_ports.items()}), ip))
            conn.commit()
            conn.close()

        set_progress(scan_id, progress=50, **msg('p_checking_vulns'))
        vulns = check_vulns(ip, open_ports, banners)
        score = risk_score(vulns)

        conn = db_conn()
        conn.execute('DELETE FROM vulnerabilities WHERE host_ip=?', (ip,))
        conn.executemany('''INSERT INTO vulnerabilities
            (host_ip, port, service, vuln_type, severity, description, recommendation, found_at)
            VALUES (?,?,?,?,?,?,?,?)''',
            [(v['host_ip'], v['port'], v['service'], v['vuln_type'], v['severity'],
              v['description'], v['recommendation'], v['found_at']) for v in vulns])
        conn.execute('UPDATE hosts SET risk_score=? WHERE ip=?', (score, ip))
        conn.execute('INSERT INTO scans (scan_type, target, started_at, finished_at, status, results) VALUES (?,?,?,?,?,?)',
                     ('vulns', ip, datetime.now().isoformat(), datetime.now().isoformat(), 'completed', json.dumps(len(vulns))))
        conn.commit()
        conn.close()
        set_progress(scan_id, status='done', progress=100, vulns=vulns, risk_score=score,
                     **msg('p_vulns_done', n=len(vulns), score=score))
    except BadInput as e:
        set_progress(scan_id, status='error', **msg(e.key, **e.params))
    except Exception as e:
        set_progress(scan_id, status='error', **msg('err_generic', error=str(e)[:200]))


def run_simple(scan_id, fn, target):
    set_progress(scan_id, status='running', progress=10, **msg('p_running'))
    try:
        results = fn(target)
        set_progress(scan_id, status='done', progress=100, results=results, **msg('p_done'))
    except Exception as e:
        set_progress(scan_id, status='error', **msg('err_generic', error=str(e)[:200]))


def launch_scan(scan_type, target, options=None, port_range='common'):
    """Valida y lanza un escaneo en segundo plano. Devuelve su id."""
    if scan_type == 'discovery':
        target = str(parse_network(target))
        fn, args = run_discovery_scan, (target, options or {})
    elif scan_type == 'ports':
        target = parse_ip(target)
        parse_ports(port_range)
        fn, args = run_port_scan, (target, port_range)
    elif scan_type == 'vulns':
        target = parse_ip(target)
        fn, args = run_vuln_scan, (target,)
    elif scan_type == 'dns':
        target = parse_domain(target)
        fn, args = run_simple, (dns_enum, target)
    elif scan_type == 'smb':
        target = parse_ip(target)
        fn, args = run_simple, (smb_enum, target)
    else:
        raise BadInput('err_unknown_type')
    scan_id = secrets.token_hex(6)
    set_progress(scan_id, status='queued', progress=0, started_at=datetime.now().isoformat(), **msg('p_queued'))
    threading.Thread(target=fn, args=(scan_id, *args), daemon=True).start()
    return scan_id


# ─────────────────────────────────────────────
# PROGRAMADOR (antes las tareas se guardaban pero nunca se ejecutaban)
# ─────────────────────────────────────────────
INTERVALS = {'hourly': timedelta(hours=1), 'daily': timedelta(days=1), 'weekly': timedelta(weeks=1)}


def next_run_from(schedule, base=None):
    delta = INTERVALS.get(schedule)
    return (base or datetime.now()) + delta if delta else None


def run_task(task):
    scan_id = launch_scan(task['scan_type'], task['target'],
                          {'os_detect': True, 'resolve_hostnames': True, 'vendor_lookup': True})
    now = datetime.now()
    nxt = next_run_from(task['schedule'], now)
    conn = db_conn()
    conn.execute('UPDATE scheduled_tasks SET last_run=?, next_run=? WHERE id=?',
                 (now.isoformat(timespec='seconds'), nxt.isoformat(timespec='seconds') if nxt else None, task['id']))
    conn.commit()
    conn.close()
    return scan_id


def scheduler_loop():
    while True:
        time.sleep(30)
        try:
            conn = db_conn()
            due = conn.execute("SELECT * FROM scheduled_tasks WHERE enabled=1 AND next_run IS NOT NULL AND next_run <= ?",
                               (datetime.now().isoformat(timespec='seconds'),)).fetchall()
            conn.close()
            for task in due:
                try:
                    run_task(dict(task))
                    print(f"  [scheduler] {task['name']} → {task['scan_type']} {task['target']}")
                except Exception as e:
                    print(f"  [scheduler] {task['name']} failed: {e}")
        except Exception:
            pass


# ─────────────────────────────────────────────
# INFORMES (todo el contenido escapado: banners y nombres vienen de la red)
# ─────────────────────────────────────────────
REPORT_TEXT = {
    'es': {'title': 'Nirvana LAN — Informe de auditoría', 'generated': 'Generado', 'summary': 'Resumen',
           'hosts': 'Equipos descubiertos', 'findings': 'Hallazgos', 'total': 'Total de hallazgos',
           'critical': 'Críticos', 'high': 'Altos', 'medium': 'Medios', 'low': 'Bajos',
           'cols_h': ['IP', 'Nombre', 'MAC', 'Fabricante', 'SO', 'Puertos abiertos', 'Riesgo', 'Visto'],
           'cols_v': ['Equipo', 'Puerto', 'Servicio', 'Tipo', 'Severidad', 'Descripción', 'Recomendación'],
           'notes': 'Notas', 'none': 'Sin datos'},
    'en': {'title': 'Nirvana LAN — Security audit report', 'generated': 'Generated', 'summary': 'Executive summary',
           'hosts': 'Discovered hosts', 'findings': 'Vulnerability findings', 'total': 'Total findings',
           'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low',
           'cols_h': ['IP', 'Hostname', 'MAC', 'Vendor', 'OS', 'Open ports', 'Risk', 'Last seen'],
           'cols_v': ['Host', 'Port', 'Service', 'Type', 'Severity', 'Description', 'Recommendation'],
           'notes': 'Notes', 'none': 'No data'},
}


def report_data():
    conn = db_conn()
    hosts = [dict(r) for r in conn.execute('SELECT * FROM hosts').fetchall()]
    vulns = [dict(r) for r in conn.execute('SELECT * FROM vulnerabilities').fetchall()]
    conn.close()
    hosts.sort(key=lambda h: ipaddress.IPv4Address(h['ip']) if _is_ip(h['ip']) else ipaddress.IPv4Address('0.0.0.0'))
    vulns.sort(key=lambda v: (SEVERITY_ORDER.get(v['severity'], 9), v['host_ip'], v['port'] or 0))
    for h in hosts:
        try:
            h['ports_list'] = sorted(int(p) for p in json.loads(h['open_ports'] or '{}'))
        except Exception:
            h['ports_list'] = []
    return hosts, vulns


def _is_ip(v):
    try:
        ipaddress.IPv4Address(v)
        return True
    except Exception:
        return False


def generate_html_report(lang='es'):
    T = REPORT_TEXT.get(lang, REPORT_TEXT['es'])
    e = lambda v: html.escape('' if v is None else str(v))
    hosts, vulns = report_data()
    counts = {k: sum(1 for v in vulns if v['severity'] == k) for k in SEVERITY_ORDER}
    now = datetime.now()
    out = [f"""<!DOCTYPE html><html lang="{lang}"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>{e(T['title'])} {now:%Y-%m-%d}</title>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;margin:0;padding:24px;line-height:1.45}}
h1{{color:#00d4ff;margin:0 0 4px}} h2{{color:#a78bfa;border-bottom:1px solid #333;padding-bottom:6px;margin-top:32px}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700}}
.CRITICAL{{background:#7f1d1d;color:#fca5a5}} .HIGH{{background:#7c2d12;color:#fdba74}}
.MEDIUM{{background:#713f12;color:#fcd34d}} .LOW{{background:#1e3a5f;color:#93c5fd}} .INFO{{background:#1e293b;color:#94a3b8}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}} th{{background:#1e293b;padding:8px;text-align:left}}
td{{border-bottom:1px solid #1e293b;padding:8px;vertical-align:top}} .mono{{font-family:Consolas,monospace}}
.stat{{display:inline-block;background:#1e293b;padding:14px 22px;border-radius:8px;margin:6px;text-align:center}}
.stat b{{display:block;font-size:2em;color:#00d4ff}} footer{{color:#64748b;text-align:center;margin-top:40px;font-size:12px}}
@media print{{body{{background:#fff;color:#111}} th,.stat{{background:#eee}} td{{border-color:#ccc}}}}
</style></head><body>
<h1>{e(T['title'])}</h1><p>{e(T['generated'])}: {now:%Y-%m-%d %H:%M:%S}</p>
<h2>{e(T['summary'])}</h2><div>
<div class="stat"><b>{len(hosts)}</b>{e(T['hosts'])}</div>
<div class="stat"><b style="color:#ef4444">{counts['CRITICAL']}</b>{e(T['critical'])}</div>
<div class="stat"><b style="color:#f97316">{counts['HIGH']}</b>{e(T['high'])}</div>
<div class="stat"><b style="color:#eab308">{counts['MEDIUM']}</b>{e(T['medium'])}</div>
<div class="stat"><b style="color:#3b82f6">{counts['LOW']}</b>{e(T['low'])}</div>
<div class="stat"><b>{len(vulns)}</b>{e(T['total'])}</div></div>
<h2>{e(T['hosts'])}</h2><table><tr>{''.join(f'<th>{e(c)}</th>' for c in T['cols_h'])}</tr>"""]
    for h in hosts:
        risk = h['risk_score'] or 0
        color = '#ef4444' if risk >= 70 else '#f97316' if risk >= 40 else '#eab308' if risk >= 20 else '#22c55e'
        hostname = h['hostname'] if h['hostname'] and h['hostname'] != h['ip'] else '-'
        out.append(f"<tr><td class='mono'>{e(h['ip'])}</td><td>{e(hostname)}</td><td class='mono'>{e(h['mac'] or '-')}</td>"
                   f"<td>{e(h['vendor'] or '-')}</td><td>{e(h['os_guess'] or '-')}</td>"
                   f"<td class='mono'>{e(', '.join(map(str, h['ports_list'])) or '-')}</td>"
                   f"<td style='color:{color};font-weight:700'>{int(risk)}</td><td>{e((h['last_seen'] or '-')[:16].replace('T', ' '))}</td></tr>")
        if h.get('notes'):
            out.append(f"<tr><td></td><td colspan='7'><i>{e(T['notes'])}:</i> {e(h['notes'])}</td></tr>")
    if not hosts:
        out.append(f"<tr><td colspan='8'>{e(T['none'])}</td></tr>")
    out.append(f"</table><h2>{e(T['findings'])}</h2><table><tr>{''.join(f'<th>{e(c)}</th>' for c in T['cols_v'])}</tr>")
    for v in vulns:
        sev = v['severity'] if v['severity'] in SEVERITY_ORDER else 'INFO'
        out.append(f"<tr><td class='mono'>{e(v['host_ip'])}</td><td>{e(v['port'])}</td><td>{e(v['service'])}</td>"
                   f"<td class='mono'>{e(v['vuln_type'])}</td><td><span class='badge {sev}'>{sev}</span></td>"
                   f"<td>{e(v['description'])}</td><td>{e(v['recommendation'])}</td></tr>")
    if not vulns:
        out.append(f"<tr><td colspan='7'>{e(T['none'])}</td></tr>")
    out.append(f"</table><footer>Nirvana LAN · Un fantasma en el sistema · unfantasmaenelsistema.com · {now.year}</footer></body></html>")
    return ''.join(out)


def generate_txt_report(lang='es'):
    T = REPORT_TEXT.get(lang, REPORT_TEXT['es'])
    hosts, vulns = report_data()
    lines = ['=' * 72, f"  {T['title']}", f"  {T['generated']}: {datetime.now():%Y-%m-%d %H:%M:%S}", '=' * 72, '',
             T['hosts'].upper(), '-' * 72]
    for h in hosts:
        lines.append(f"  IP: {h['ip']:<16} MAC: {h['mac'] or 'N/A':<18} {T['cols_h'][1]}: {h['hostname'] or 'N/A'}")
        lines.append(f"  {T['cols_h'][3]}: {h['vendor'] or 'N/A':<16} {T['cols_h'][4]}: {h['os_guess'] or 'N/A':<26} {T['cols_h'][6]}: {h['risk_score'] or 0}")
        if h['ports_list']:
            lines.append(f"  {T['cols_h'][5]}: {', '.join(map(str, h['ports_list']))}")
        if h.get('notes'):
            lines.append(f"  {T['notes']}: {h['notes']}")
        lines.append('')
    lines += ['', T['findings'].upper(), '-' * 72]
    for v in vulns:
        lines.append(f"  [{v['severity']}] {v['host_ip']}:{v['port']} ({v['service']}) - {v['vuln_type']}")
        lines.append(f"    {v['description']}")
        lines.append(f"    → {v['recommendation']}")
        lines.append('')
    return '\n'.join(lines)


# ─────────────────────────────────────────────
# PROTECCIÓN DE LA API
# - Solo responde si el Host es el esperado (frena DNS rebinding).
# - Las peticiones que cambian algo exigen la cabecera X-Nirvana, que un
#   sitio web ajeno no puede enviar sin una preflight CORS que se deniega.
# ─────────────────────────────────────────────
ALLOWED_HOSTS = set()


@app.before_request
def guard():
    host = (request.host or '').lower()
    if ALLOWED_HOSTS and host not in ALLOWED_HOSTS:
        abort(403)
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH') and request.headers.get('X-Nirvana') != '1':
        abort(403)


@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    if resp.mimetype == 'text/html' and request.path == '/':
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
    return resp


def bad_request(e):
    return jsonify({'error': e.key, 'params': e.params}), 400


# ─────────────────────────────────────────────
# RUTAS
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/network-info')
def api_network_info():
    networks = get_local_networks()
    suggested = next((n['network'] for n in networks if int(n['cidr']) >= 22), None)
    if not suggested and networks:
        net = ipaddress.IPv4Network(f"{networks[0]['ip']}/24", strict=False)
        suggested = str(net)
    return jsonify({'networks': networks, 'hostname': socket.gethostname(), 'suggested': suggested,
                    'platform': platform.system(), 'demo': False})


def host_json(r, vulns=None):
    try:
        ports = json.loads(r['open_ports']) if r['open_ports'] else {}
    except Exception:
        ports = {}
    d = {'id': r['id'], 'ip': r['ip'], 'mac': r['mac'], 'hostname': r['hostname'], 'vendor': r['vendor'],
         'os_guess': r['os_guess'], 'status': r['status'], 'open_ports': ports, 'last_seen': r['last_seen'],
         'risk_score': r['risk_score'] or 0, 'notes': r['notes']}
    if vulns is not None:
        d['vulnerabilities'] = vulns
    return d


@app.route('/api/hosts')
def api_hosts():
    conn = db_conn()
    rows = conn.execute('SELECT * FROM hosts').fetchall()
    conn.close()
    hosts = [host_json(r) for r in rows]
    hosts.sort(key=lambda h: ipaddress.IPv4Address(h['ip']) if _is_ip(h['ip']) else ipaddress.IPv4Address('0.0.0.0'))
    return jsonify(hosts)


@app.route('/api/hosts/<ip>', methods=['GET'])
def api_host_detail(ip):
    conn = db_conn()
    row = conn.execute('SELECT * FROM hosts WHERE ip=?', (ip,)).fetchone()
    vulns = conn.execute('SELECT * FROM vulnerabilities WHERE host_ip=?', (ip,)).fetchall()
    conn.close()
    if not row:
        return jsonify({'error': 'err_host_not_found'}), 404
    vl = [{k: v[k] for k in ('port', 'service', 'vuln_type', 'severity', 'description', 'recommendation')} for v in vulns]
    vl.sort(key=lambda v: SEVERITY_ORDER.get(v['severity'], 9))
    return jsonify(host_json(row, vl))


@app.route('/api/hosts/<ip>/notes', methods=['POST'])
def api_update_notes(ip):
    notes = str((request.get_json(silent=True) or {}).get('notes', ''))[:4000]
    conn = db_conn()
    conn.execute('UPDATE hosts SET notes=? WHERE ip=?', (notes, ip))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    data = request.get_json(silent=True) or {}
    try:
        scan_id = launch_scan(data.get('type', 'discovery'), data.get('target', ''),
                              data.get('options') or {}, data.get('port_range', 'common'))
    except BadInput as e:
        return bad_request(e)
    return jsonify({'scan_id': scan_id})


@app.route('/api/scan/status/<scan_id>')
def api_scan_status(scan_id):
    with progress_lock:
        data = json.loads(json.dumps(scan_progress.get(scan_id, {'status': 'not_found'})))
    return jsonify(data)


@app.route('/api/vulnerabilities')
def api_vulns():
    conn = db_conn()
    rows = conn.execute('SELECT * FROM vulnerabilities').fetchall()
    conn.close()
    vulns = [dict(r) for r in rows]
    vulns.sort(key=lambda v: (SEVERITY_ORDER.get(v['severity'], 9), v['host_ip']))
    return jsonify(vulns)


@app.route('/api/stats')
def api_stats():
    conn = db_conn()
    q = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
    stats = {
        'total_hosts': q('SELECT COUNT(*) FROM hosts'),
        'up_hosts': q("SELECT COUNT(*) FROM hosts WHERE status='up'"),
        'total_vulns': q('SELECT COUNT(*) FROM vulnerabilities'),
        'critical': q("SELECT COUNT(*) FROM vulnerabilities WHERE severity='CRITICAL'"),
        'high': q("SELECT COUNT(*) FROM vulnerabilities WHERE severity='HIGH'"),
        'medium': q("SELECT COUNT(*) FROM vulnerabilities WHERE severity='MEDIUM'"),
        'low': q("SELECT COUNT(*) FROM vulnerabilities WHERE severity='LOW'"),
        'scans': q('SELECT COUNT(*) FROM scans'),
    }
    port_counts = {}
    for row in conn.execute("SELECT open_ports FROM hosts WHERE open_ports IS NOT NULL AND open_ports != ''"):
        try:
            for p in json.loads(row['open_ports']):
                port_counts[int(p)] = port_counts.get(int(p), 0) + 1
        except Exception:
            pass
    conn.close()
    top = sorted(port_counts.items(), key=lambda x: (-x[1], x[0]))[:10]
    stats['top_ports'] = [{'port': p, 'service': COMMON_PORTS.get(p, 'unknown'), 'count': c} for p, c in top]
    return jsonify(stats)


def _lang():
    return 'en' if request.args.get('lang') == 'en' else 'es'


@app.route('/api/report/html')
def api_report_html():
    buf = io.BytesIO(generate_html_report(_lang()).encode('utf-8'))
    inline = request.args.get('inline') == '1'
    return send_file(buf, mimetype='text/html', as_attachment=not inline,
                     download_name=f'nirvana_lan_report_{datetime.now():%Y%m%d_%H%M%S}.html')


@app.route('/api/report/txt')
def api_report_txt():
    buf = io.BytesIO(generate_txt_report(_lang()).encode('utf-8'))
    return send_file(buf, mimetype='text/plain; charset=utf-8', as_attachment=True,
                     download_name=f'nirvana_lan_report_{datetime.now():%Y%m%d_%H%M%S}.txt')


@app.route('/api/hosts/clear', methods=['POST'])
def api_clear_hosts():
    conn = db_conn()
    conn.execute('DELETE FROM hosts')
    conn.execute('DELETE FROM vulnerabilities')
    conn.execute('DELETE FROM scans')
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/scheduled', methods=['GET'])
def api_get_scheduled():
    conn = db_conn()
    rows = conn.execute('SELECT * FROM scheduled_tasks ORDER BY id').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/scheduled', methods=['POST'])
def api_add_scheduled():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()[:80]
    scan_type = data.get('scan_type')
    schedule = data.get('schedule')
    target = str(data.get('target', '')).strip()
    try:
        if not name:
            raise BadInput('err_missing_fields')
        if scan_type == 'discovery':
            target = str(parse_network(target))
        elif scan_type in ('ports', 'vulns'):
            target = parse_ip(target)
        else:
            raise BadInput('err_unknown_type')
        if schedule not in ('hourly', 'daily', 'weekly', 'manual'):
            raise BadInput('err_bad_schedule')
    except BadInput as e:
        return bad_request(e)
    nxt = next_run_from(schedule)
    conn = db_conn()
    conn.execute('INSERT INTO scheduled_tasks (name, scan_type, target, schedule, next_run, enabled) VALUES (?,?,?,?,?,1)',
                 (name, scan_type, target, schedule, nxt.isoformat(timespec='seconds') if nxt else None))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/scheduled/<int:task_id>/run', methods=['POST'])
def api_run_scheduled(task_id):
    conn = db_conn()
    row = conn.execute('SELECT * FROM scheduled_tasks WHERE id=?', (task_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'err_task_not_found'}), 404
    try:
        return jsonify({'scan_id': run_task(dict(row)), 'scan_type': row['scan_type']})
    except BadInput as e:
        return bad_request(e)


@app.route('/api/scheduled/<int:task_id>', methods=['DELETE'])
def api_del_scheduled(task_id):
    conn = db_conn()
    conn.execute('DELETE FROM scheduled_tasks WHERE id=?', (task_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ─────────────────────────────────────────────
# ARRANQUE
# ─────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='Nirvana LAN — auditoría de red local')
    ap.add_argument('--port', type=int, default=7777)
    ap.add_argument('--lan', action='store_true',
                    help='escuchar en todas las interfaces (cualquiera de la red podría usar el panel)')
    ap.add_argument('--no-browser', action='store_true', help='no abrir el navegador')
    args = ap.parse_args()

    init_db()
    bind = '0.0.0.0' if args.lan else '127.0.0.1'
    ALLOWED_HOSTS.update({f'localhost:{args.port}', f'127.0.0.1:{args.port}'})
    if args.lan:
        ALLOWED_HOSTS.update(f"{n['ip']}:{args.port}" for n in get_local_networks())

    threading.Thread(target=scheduler_loop, daemon=True).start()

    url = f'http://localhost:{args.port}'
    print('\n' + '=' * 56)
    print('  NIRVANA LAN - Network Audit Tool')
    print('  Un fantasma en el sistema · unfantasmaenelsistema.com')
    print('=' * 56)
    print(f'  Panel: {url}')
    if args.lan:
        print('  AVISO: --lan expone el panel (sin contraseña) a toda la red.')
    print('  Úsala solo en redes propias o con autorización.')
    print('  Ctrl+C para salir')
    print('=' * 56 + '\n')

    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    app.run(host=bind, port=args.port, debug=False, threaded=True)


if __name__ == '__main__':
    main()
