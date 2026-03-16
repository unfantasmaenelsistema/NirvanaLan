#!/usr/bin/env python3
"""
Nirvana LAN - Network Audit Tool
Cross-platform (Windows/Linux) network auditing with web interface
"""

import os
import sys
import json
import time
import threading
import webbrowser
import sqlite3
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file
import socket
import subprocess
import platform
import struct
import re
import ipaddress
import concurrent.futures
import psutil
import hashlib
import io

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'nirvana.db')

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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # named column access: row['ip']
    return conn


def row_to_dict(row):
    """Convert sqlite3.Row to plain dict safely"""
    if row is None:
        return None
    return dict(row)

# ─────────────────────────────────────────────
# NETWORK UTILITIES
# ─────────────────────────────────────────────

def get_local_networks():
    """Detect local network interfaces and subnets — robust multi-method"""
    networks = []
    seen_networks = set()

    # Method 1: psutil (cross-platform)
    try:
        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            # Skip loopback and down interfaces
            iface_stats = stats.get(iface)
            if iface_stats and not iface_stats.isup:
                continue
            for addr in addrs:
                if addr.family != socket.AF_INET:
                    continue
                ip = addr.address
                netmask = addr.netmask
                # Skip loopback, link-local, and empty
                if not ip or ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                if not netmask or netmask == '0.0.0.0':
                    netmask = '255.255.255.0'  # Assume /24 fallback
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    net_str = str(net)
                    if net_str not in seen_networks and net.prefixlen <= 30:
                        seen_networks.add(net_str)
                        networks.append({
                            'interface': iface,
                            'ip': ip,
                            'netmask': netmask,
                            'network': net_str,
                            'cidr': str(net.prefixlen)
                        })
                except Exception:
                    pass
    except Exception:
        pass

    # Method 2: socket gethostbyname fallback
    if not networks:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip and not local_ip.startswith('127.'):
                net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                networks.append({
                    'interface': 'default',
                    'ip': local_ip,
                    'netmask': '255.255.255.0',
                    'network': str(net),
                    'cidr': '24'
                })
        except Exception:
            pass

    # Method 3: OS-specific ip/ipconfig command
    if not networks:
        try:
            system = platform.system().lower()
            if system == 'windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
                ip_pattern = re.compile(r'IPv4 Address[.\s]+:\s*([\d.]+)')
                mask_pattern = re.compile(r'Subnet Mask[.\s]+:\s*([\d.]+)')
                ips = ip_pattern.findall(result.stdout)
                masks = mask_pattern.findall(result.stdout)
                for ip, mask in zip(ips, masks):
                    if not ip.startswith('127.'):
                        try:
                            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                            networks.append({
                                'interface': 'detected',
                                'ip': ip, 'netmask': mask,
                                'network': str(net), 'cidr': str(net.prefixlen)
                            })
                        except Exception:
                            pass
            else:
                for cmd in [['ip', 'addr'], ['ifconfig', '-a']]:
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        # Match "inet 192.168.x.x/24" or "inet addr:192.168.x.x ... Mask:255.255.255.0"
                        for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)[/\s](\S+)', result.stdout):
                            ip = match.group(1)
                            cidr_or_mask = match.group(2).rstrip(':')
                            if ip.startswith('127.') or ip.startswith('169.254.'):
                                continue
                            try:
                                if '.' in cidr_or_mask:
                                    net = ipaddress.IPv4Network(f"{ip}/{cidr_or_mask}", strict=False)
                                else:
                                    net = ipaddress.IPv4Network(f"{ip}/{cidr_or_mask}", strict=False)
                                net_str = str(net)
                                if net_str not in seen_networks and net.prefixlen <= 30:
                                    seen_networks.add(net_str)
                                    networks.append({
                                        'interface': 'detected',
                                        'ip': ip,
                                        'netmask': str(net.netmask),
                                        'network': net_str,
                                        'cidr': str(net.prefixlen)
                                    })
                            except Exception:
                                pass
                        if networks:
                            break
                    except Exception:
                        pass
        except Exception:
            pass

    # Sort: prefer private RFC1918 ranges (/24 preferred), larger subnets first
    def net_priority(n):
        ip = n['ip']
        cidr = int(n['cidr'])
        # Prefer 192.168.x.x, then 10.x.x.x, then 172.16.x.x
        if ip.startswith('192.168.'): score = 0
        elif ip.startswith('10.'): score = 1
        elif ip.startswith('172.'): score = 2
        else: score = 3
        return (score, cidr)

    networks.sort(key=net_priority)
    return networks

def ping_host(ip, timeout=1):
    """Cross-platform ping with multiple fallback methods"""
    # Method 1: system ping command
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), str(ip)]
    else:
        cmd = ['ping', '-c', '1', '-W', str(timeout), str(ip)]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        if result.returncode == 0:
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except Exception:
        pass

    # Method 2: TCP connect to common ports (works without ping/root)
    return tcp_alive(ip, timeout)


def tcp_alive(ip, timeout=1):
    """Check if host is alive via TCP connect to common ports"""
    check_ports = [80, 443, 22, 445, 139, 135, 3389, 8080, 21, 23, 8443, 8888, 3306, 5900, 53]
    for port in check_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout * 0.4)
            r = s.connect_ex((ip, port))
            s.close()
            if r == 0:
                return True
        except Exception:
            pass
    return False

def arp_scan(network):
    """ARP scan — reads OS ARP cache and optionally triggers population via ping flood"""
    hosts = {}
    system = platform.system().lower()

    def parse_arp_output(output, is_windows=False):
        result = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if is_windows:
                # Windows: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
                parts = line.split()
                if len(parts) >= 2:
                    ip_str = parts[0]
                    mac_raw = parts[1]
                    mac = mac_raw.replace('-', ':').lower()
                    try:
                        ipaddress.IPv4Address(ip_str)
                        if (not ip_str.endswith('.255') and
                                not ip_str.startswith('224.') and
                                ip_str != '255.255.255.255' and
                                mac not in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')):
                            result[ip_str] = {'mac': mac, 'source': 'arp'}
                    except Exception:
                        pass
            else:
                # Linux arp -n: "192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  eth0"
                # or arp -a:    "hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
                parts = line.split()
                # Try "arp -a" format: hostname (IP) at MAC
                match_a = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)', line, re.IGNORECASE)
                if match_a:
                    ip_str, mac = match_a.group(1), match_a.group(2).lower()
                    if mac not in ('(incomplete)', '<incomplete>', 'ff:ff:ff:ff:ff:ff'):
                        result[ip_str] = {'mac': mac, 'source': 'arp'}
                    continue
                # Try "arp -n" format: IP  HW  MAC  flags  iface
                if len(parts) >= 3:
                    ip_str = parts[0]
                    mac = parts[2].lower()
                    try:
                        ipaddress.IPv4Address(ip_str)
                        if (mac not in ('(incomplete)', '<incomplete>', 'ff:ff:ff:ff:ff:ff') and
                                ':' in mac and mac != '00:00:00:00:00:00'):
                            result[ip_str] = {'mac': mac, 'source': 'arp'}
                    except Exception:
                        pass
        return result

    try:
        if system == 'windows':
            r = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
            hosts.update(parse_arp_output(r.stdout, is_windows=True))
        else:
            # Try both arp -n and arp -a for maximum compatibility
            for args in [['arp', '-n'], ['arp', '-a']]:
                try:
                    r = subprocess.run(args, capture_output=True, text=True, timeout=8)
                    parsed = parse_arp_output(r.stdout, is_windows=False)
                    hosts.update(parsed)
                    if parsed:
                        break
                except FileNotFoundError:
                    pass

            # Also try reading /proc/net/arp directly (Linux only, most reliable)
            try:
                with open('/proc/net/arp', 'r') as f:
                    for line in f.readlines()[1:]:  # skip header
                        parts = line.split()
                        if len(parts) >= 4:
                            ip_str = parts[0]
                            mac = parts[3].lower()
                            flags = parts[2]
                            if (mac not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff') and
                                    ':' in mac and flags != '0x0'):
                                try:
                                    ipaddress.IPv4Address(ip_str)
                                    hosts[ip_str] = {'mac': mac, 'source': 'proc_arp'}
                                except Exception:
                                    pass
            except Exception:
                pass

    except Exception:
        pass

    return hosts

def get_mac_vendor(mac):
    """Get vendor from MAC OUI prefix (built-in database)"""
    oui_db = {
        '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:1c:42': 'Parallels',
        'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
        '00:1a:11': 'Google', 'f4:f5:d8': 'Google', '54:60:09': 'Google',
        'ac:bc:32': 'Apple', '00:03:93': 'Apple', '00:05:02': 'Apple',
        '3c:22:fb': 'Apple', '8c:85:90': 'Apple', 'f0:18:98': 'Apple',
        '00:1b:21': 'Intel', '00:21:6a': 'Intel', '8c:8d:28': 'Intel',
        '00:1d:60': 'Cisco', '00:1e:13': 'Cisco', '00:1f:ca': 'Cisco',
        'a4:c3:f0': 'Raspberry Pi', '28:cd:c1': 'Apple', '78:4f:43': 'Dell',
        'f8:b1:56': 'Dell', '00:14:22': 'Dell', '00:21:9b': 'Dell',
        '00:50:ba': 'D-Link', '00:1c:f0': 'D-Link', '14:d6:4d': 'D-Link',
        'c8:3a:35': 'TP-Link', 'f4:ec:38': 'TP-Link', '50:c7:bf': 'TP-Link',
        '00:90:f5': 'ASUS', '00:1f:c6': 'ASUS', '04:d9:f5': 'ASUS',
        '00:23:ae': 'Netgear', 'a0:21:b7': 'Netgear', '20:4e:7f': 'Netgear',
        '00:25:9c': 'Cisco Linksys', 'c0:c1:c0': 'Cisco Linksys',
        '00:11:22': 'Cimsys', 'fc:fb:fb': 'Synology',
    }
    if not mac or mac in ('(incomplete)', '--'):
        return 'Unknown'
    prefix = mac[:8].lower()
    for oui, vendor in oui_db.items():
        if prefix == oui.lower():
            return vendor
    return 'Unknown'

def resolve_hostname(ip):
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def scan_port(ip, port, timeout=1):
    """TCP port scan"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_service_banner(ip, port, timeout=2):
    """Grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        try:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        except:
            try:
                banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            except:
                banner = ''
        sock.close()
        return banner[:200]
    except:
        return ''

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3',
    111: 'RPC', 119: 'NNTP', 123: 'NTP', 135: 'MSRPC', 137: 'NetBIOS',
    138: 'NetBIOS', 139: 'NetBIOS/SMB', 143: 'IMAP', 161: 'SNMP',
    194: 'IRC', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 515: 'LPD', 587: 'SMTP', 631: 'IPP', 636: 'LDAPS',
    873: 'rsync', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
    1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
    2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel SSL', 2222: 'SSH alt',
    3000: 'HTTP dev', 3306: 'MySQL', 3389: 'RDP', 3690: 'SVN',
    4443: 'HTTPS alt', 5000: 'Flask', 5432: 'PostgreSQL', 5900: 'VNC',
    5985: 'WinRM HTTP', 5986: 'WinRM HTTPS', 6379: 'Redis',
    7070: 'RTSP', 8000: 'HTTP alt', 8080: 'HTTP proxy', 8443: 'HTTPS alt',
    8888: 'Jupyter', 9000: 'SonarQube', 9090: 'Prometheus', 9200: 'Elasticsearch',
    10000: 'Webmin', 27017: 'MongoDB', 50000: 'SAP'
}

def scan_ports_range(ip, ports, callback=None):
    """Scan a list of ports concurrently"""
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                service = COMMON_PORTS.get(port, 'unknown')
                open_ports[port] = service
                if callback:
                    callback(port, service)
    return open_ports

def os_fingerprint(ip):
    """Basic OS fingerprinting via TTL and other hints"""
    system = platform.system().lower()
    try:
        if system == 'windows':
            cmd = ['ping', '-n', '1', str(ip)]
        else:
            cmd = ['ping', '-c', '1', str(ip)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        output = result.stdout + result.stderr
        
        # Extract TTL
        ttl_match = re.search(r'ttl[=\s]+(\d+)', output, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                return 'Linux/Unix (TTL≤64)'
            elif ttl <= 128:
                return 'Windows (TTL≤128)'
            elif ttl <= 255:
                return 'Network Device (TTL≤255)'
    except:
        pass
    return 'Unknown'

# ─────────────────────────────────────────────
# DNS ENUMERATION
# ─────────────────────────────────────────────

def dns_enum(target):
    """DNS enumeration"""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    for rtype in record_types:
        try:
            if platform.system().lower() == 'windows':
                cmd = ['nslookup', f'-type={rtype}', target]
            else:
                cmd = ['dig', '+short', rtype, target]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = proc.stdout.strip()
            if output:
                results[rtype] = output.splitlines()
        except:
            pass
    
    # Try zone transfer
    try:
        ns_cmd = ['dig', '+short', 'NS', target] if platform.system().lower() != 'windows' \
                 else ['nslookup', '-type=NS', target]
        ns_proc = subprocess.run(ns_cmd, capture_output=True, text=True, timeout=5)
        nameservers = [line.strip().rstrip('.') for line in ns_proc.stdout.splitlines() if line.strip()]
        
        axfr_results = []
        for ns in nameservers[:3]:
            try:
                axfr_cmd = ['dig', f'@{ns}', target, 'AXFR']
                axfr = subprocess.run(axfr_cmd, capture_output=True, text=True, timeout=8)
                if 'Transfer failed' not in axfr.stdout and axfr.stdout.strip():
                    axfr_results.append(f"Zone transfer from {ns}:\n{axfr.stdout[:500]}")
            except:
                pass
        if axfr_results:
            results['AXFR'] = axfr_results
    except:
        pass
    
    return results

# ─────────────────────────────────────────────
# SMB ENUMERATION
# ─────────────────────────────────────────────

def smb_enum(ip):
    """SMB enumeration"""
    results = {'shares': [], 'signing': None, 'version': None, 'users': []}
    
    # Check SMB ports
    smb_open = scan_port(ip, 445) or scan_port(ip, 139)
    if not smb_open:
        return results
    
    results['port_open'] = True
    
    # Try smbclient
    try:
        cmd = ['smbclient', '-L', ip, '-N', '--no-pass']
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        output = proc.stdout + proc.stderr
        
        share_pattern = re.compile(r'^\s+(\S+)\s+(Disk|IPC|Printer)', re.MULTILINE | re.IGNORECASE)
        for match in share_pattern.finditer(output):
            results['shares'].append({'name': match.group(1), 'type': match.group(2)})
    except:
        pass
    
    # Try rpcclient for users
    try:
        cmd = ['rpcclient', '-U', '', '-N', ip, '-c', 'enumdomusers']
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        user_pattern = re.compile(r'user:\[([^\]]+)\]')
        results['users'] = user_pattern.findall(proc.stdout)
    except:
        pass
    
    # Banner grab for SMB signing info
    banner = get_service_banner(ip, 445)
    results['banner'] = banner
    
    return results

# ─────────────────────────────────────────────
# VULNERABILITY DETECTION
# ─────────────────────────────────────────────

VULN_CHECKS = [
    {
        'id': 'TELNET_OPEN',
        'port': 23, 'service': 'Telnet',
        'severity': 'CRITICAL',
        'description': 'Telnet transmits data in plaintext, including credentials. Highly vulnerable to MITM attacks.',
        'recommendation': 'Disable Telnet immediately. Use SSH instead.'
    },
    {
        'id': 'FTP_OPEN',
        'port': 21, 'service': 'FTP',
        'severity': 'HIGH',
        'description': 'FTP transmits credentials and data unencrypted.',
        'recommendation': 'Use SFTP or FTPS. Disable anonymous access.'
    },
    {
        'id': 'SMB_OPEN',
        'port': 445, 'service': 'SMB',
        'severity': 'HIGH',
        'description': 'SMB port exposed. Vulnerable to EternalBlue (MS17-010) and related exploits if unpatched.',
        'recommendation': 'Ensure system is fully patched. Enable SMB signing. Block if not needed.'
    },
    {
        'id': 'RDP_OPEN',
        'port': 3389, 'service': 'RDP',
        'severity': 'HIGH',
        'description': 'RDP exposed to network. Susceptible to BlueKeep (CVE-2019-0708) and brute force.',
        'recommendation': 'Restrict access via VPN. Enable NLA. Keep patched.'
    },
    {
        'id': 'MSSQL_OPEN',
        'port': 1433, 'service': 'MSSQL',
        'severity': 'HIGH',
        'description': 'MSSQL database port exposed. Risk of SQL injection and credential attacks.',
        'recommendation': 'Restrict access. Disable SA account. Use strong passwords.'
    },
    {
        'id': 'MYSQL_OPEN',
        'port': 3306, 'service': 'MySQL',
        'severity': 'HIGH',
        'description': 'MySQL database exposed to network. Risk of unauthorized access.',
        'recommendation': 'Bind to localhost only. Use strong credentials.'
    },
    {
        'id': 'MONGODB_OPEN',
        'port': 27017, 'service': 'MongoDB',
        'severity': 'CRITICAL',
        'description': 'MongoDB may be running without authentication.',
        'recommendation': 'Enable authentication. Bind to specific interfaces only.'
    },
    {
        'id': 'REDIS_OPEN',
        'port': 6379, 'service': 'Redis',
        'severity': 'CRITICAL',
        'description': 'Redis often has no authentication by default. Full data access risk.',
        'recommendation': 'Enable requirepass in redis.conf. Restrict network access.'
    },
    {
        'id': 'VNC_OPEN',
        'port': 5900, 'service': 'VNC',
        'severity': 'HIGH',
        'description': 'VNC exposes desktop remotely. Often weakly authenticated.',
        'recommendation': 'Use strong password. Tunnel through SSH. Restrict access.'
    },
    {
        'id': 'ELASTICSEARCH_OPEN',
        'port': 9200, 'service': 'Elasticsearch',
        'severity': 'CRITICAL',
        'description': 'Elasticsearch may be accessible without authentication, exposing all indexed data.',
        'recommendation': 'Enable X-Pack security. Restrict to localhost.'
    },
    {
        'id': 'SNMP_OPEN',
        'port': 161, 'service': 'SNMP',
        'severity': 'MEDIUM',
        'description': 'SNMP v1/v2c uses community strings in plaintext.',
        'recommendation': 'Use SNMPv3 with authentication. Change default community strings.'
    },
    {
        'id': 'HTTP_OPEN',
        'port': 80, 'service': 'HTTP',
        'severity': 'LOW',
        'description': 'HTTP transmits data unencrypted.',
        'recommendation': 'Migrate to HTTPS. Implement HSTS.'
    },
    {
        'id': 'SSH_OPEN',
        'port': 22, 'service': 'SSH',
        'severity': 'INFO',
        'description': 'SSH service detected. Verify key-based auth and disable root login.',
        'recommendation': 'Use key-based auth. Disable password auth. Change default port.'
    },
]

def check_vulns(ip, open_ports):
    """Check for vulnerabilities based on open ports"""
    vulns = []
    for check in VULN_CHECKS:
        if check['port'] in open_ports:
            vulns.append({
                'host_ip': ip,
                'port': check['port'],
                'service': check['service'],
                'vuln_type': check['id'],
                'severity': check['severity'],
                'description': check['description'],
                'recommendation': check['recommendation'],
                'found_at': datetime.now().isoformat()
            })
    
    # Additional banner-based checks
    for port in open_ports:
        banner = get_service_banner(ip, port)
        if banner:
            # Check for outdated software versions
            old_patterns = [
                (r'Apache/2\.[01]', 'OUTDATED_APACHE', 'HIGH', 'Outdated Apache version detected.', 'Update to latest Apache 2.4.x'),
                (r'OpenSSH_[45]', 'OUTDATED_OPENSSH', 'HIGH', 'Old OpenSSH version detected.', 'Update OpenSSH to latest version.'),
                (r'Microsoft-IIS/[567]', 'OUTDATED_IIS', 'HIGH', 'Outdated IIS detected.', 'Update IIS or migrate to newer Windows Server.'),
                (r'vsftpd 2\.[01234]', 'OUTDATED_VSFTPD', 'MEDIUM', 'Old vsftpd version.', 'Update vsftpd.'),
                (r'Server: MiniServ', 'WEBMIN_DETECTED', 'MEDIUM', 'Webmin detected. Check for known vulnerabilities.', 'Update Webmin regularly.'),
            ]
            for pattern, vuln_id, sev, desc, rec in old_patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    vulns.append({
                        'host_ip': ip, 'port': port,
                        'service': open_ports.get(port, 'unknown'),
                        'vuln_type': vuln_id, 'severity': sev,
                        'description': f"{desc} Banner: {banner[:100]}",
                        'recommendation': rec,
                        'found_at': datetime.now().isoformat()
                    })
    return vulns

def risk_score(vulns):
    """Calculate risk score 0-100"""
    if not vulns:
        return 0
    severity_scores = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5, 'INFO': 1}
    score = sum(severity_scores.get(v['severity'], 0) for v in vulns)
    return min(100, score)

# ─────────────────────────────────────────────
# SCAN MANAGER
# ─────────────────────────────────────────────

scan_progress = {}
scan_results_cache = {}

def run_discovery_scan(scan_id, network, options):
    """Main discovery scan"""
    started_at = datetime.now().isoformat()
    scan_progress[scan_id] = {
        'status': 'running', 'progress': 0,
        'message': 'Starting...', 'hosts': [],
        'started_at': started_at
    }

    try:
        net = ipaddress.IPv4Network(network, strict=False)
        hosts_list = list(net.hosts())
        total = len(hosts_list)

        if total == 0:
            scan_progress[scan_id]['status'] = 'error'
            scan_progress[scan_id]['message'] = 'No hosts in this range (check CIDR notation)'
            return

        if total > 4096:
            scan_progress[scan_id]['status'] = 'error'
            scan_progress[scan_id]['message'] = f'Range too large ({total} hosts). Use a /24 or smaller.'
            return

        scan_progress[scan_id]['message'] = f'Warming ARP cache for {total} hosts...'

        # Step 1: Warm ARP cache by pinging all hosts quickly (fire and forget style)
        # This populates /proc/net/arp even if ping isn't available everywhere
        def warm_arp(ip_str):
            system = platform.system().lower()
            if system == 'windows':
                cmd = ['ping', '-n', '1', '-w', '300', ip_str]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', '-q', ip_str]
            try:
                subprocess.run(cmd, capture_output=True, timeout=2)
            except Exception:
                pass

        # Warm up in fast threads (fire & forget, small batches)
        if total <= 256:
            scan_progress[scan_id]['message'] = f'Sending probes to {total} hosts...'
            with concurrent.futures.ThreadPoolExecutor(max_workers=150) as ex:
                futs = [ex.submit(warm_arp, str(ip)) for ip in hosts_list]
                concurrent.futures.wait(futs, timeout=max(5, total * 0.05))

        # Step 2: Read ARP table after warmup
        scan_progress[scan_id]['message'] = 'Reading ARP table...'
        arp_hosts = arp_scan(network)
        scan_progress[scan_id]['message'] = f'ARP found {len(arp_hosts)} hosts, running TCP checks...'

        found_hosts = []
        lock = threading.Lock()

        def check_host(ip):
            ip_str = str(ip)
            in_arp = ip_str in arp_hosts

            # If in ARP cache, host is definitely alive
            # Otherwise try TCP connect
            alive = in_arp or tcp_alive(ip_str, timeout=0.8)

            if alive:
                info = arp_hosts.get(ip_str, {})
                mac = info.get('mac', 'N/A')
                if not mac or mac == 'N/A':
                    # Try to get MAC from /proc/net/arp directly
                    try:
                        with open('/proc/net/arp', 'r') as f:
                            for line in f.readlines()[1:]:
                                parts = line.split()
                                if len(parts) >= 4 and parts[0] == ip_str:
                                    m = parts[3].lower()
                                    if m != '00:00:00:00:00:00':
                                        mac = m
                                        break
                    except Exception:
                        pass

                hostname = resolve_hostname(ip_str) if options.get('resolve_hostnames', True) else ip_str
                vendor = get_mac_vendor(mac) if options.get('vendor_lookup', True) else 'Unknown'
                os_guess = os_fingerprint(ip_str) if options.get('os_detect') else 'Unknown'

                host = {
                    'ip': ip_str,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor,
                    'os_guess': os_guess,
                    'status': 'up',
                    'last_seen': datetime.now().isoformat()
                }

                # Save to DB (thread-safe)
                try:
                    conn = db_conn()
                    conn.execute('''INSERT OR REPLACE INTO hosts
                        (ip, mac, hostname, vendor, os_guess, status, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (ip_str, mac, hostname, vendor, os_guess, 'up',
                         datetime.now().isoformat()))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

                with lock:
                    scan_progress[scan_id]['hosts'].append(host)
                    found_hosts.append(host)
                return host
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=120) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in hosts_list}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                pct = int(done / total * 100)
                scan_progress[scan_id]['progress'] = pct
                if done % 10 == 0 or done == total:
                    n_found = len(found_hosts)
                    scan_progress[scan_id]['message'] = (
                        f'Scanned {done}/{total} — Found {n_found} hosts'
                    )
                try:
                    future.result()
                except Exception:
                    pass

        scan_progress[scan_id]['status'] = 'done'
        scan_progress[scan_id]['progress'] = 100
        scan_progress[scan_id]['message'] = f'Complete! Found {len(found_hosts)} active hosts'

        # Save scan record
        try:
            conn = db_conn()
            conn.execute(
                '''INSERT INTO scans (scan_type, target, started_at, finished_at, status, results)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                ('discovery', network, started_at,
                 datetime.now().isoformat(), 'completed', json.dumps(found_hosts))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    except Exception as e:
        import traceback
        scan_progress[scan_id]['status'] = 'error'
        scan_progress[scan_id]['message'] = f'Error: {str(e)}'
        print(traceback.format_exc())

def run_port_scan(scan_id, ip, port_range='common'):
    """Port scan a specific host"""
    scan_progress[scan_id] = {'status': 'running', 'progress': 0, 'message': f'Port scanning {ip}...', 'ports': []}
    
    try:
        if port_range == 'common':
            ports = list(COMMON_PORTS.keys())
        elif port_range == 'full':
            ports = list(range(1, 65536))
        elif port_range == 'top1000':
            ports = list(range(1, 1001))
        else:
            # custom range like "80,443,8080" or "1-1024"
            if '-' in str(port_range):
                start, end = port_range.split('-')
                ports = list(range(int(start), int(end) + 1))
            else:
                ports = [int(p) for p in str(port_range).split(',')]
        
        open_ports = {}
        total = len(ports)
        done = 0
        
        def check_port(port):
            nonlocal done
            is_open = scan_port(ip, port)
            done += 1
            scan_progress[scan_id]['progress'] = int(done / total * 100)
            if is_open:
                service = COMMON_PORTS.get(port, 'unknown')
                banner = get_service_banner(ip, port) if port in [21, 22, 25, 80, 110, 143, 443, 8080] else ''
                return port, service, banner
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            futures = [executor.submit(check_port, p) for p in ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    port, service, banner = result
                    open_ports[port] = {'service': service, 'banner': banner}
                    scan_progress[scan_id]['ports'].append({'port': port, 'service': service, 'banner': banner})
        
        # Update DB
        conn = db_conn()
        _existing = conn.execute('SELECT open_ports FROM hosts WHERE ip=?', (ip,)).fetchone()
        conn.execute('UPDATE hosts SET open_ports=?, last_seen=? WHERE ip=?',
                     (json.dumps(open_ports), datetime.now().isoformat(), ip))
        conn.commit()
        conn.close()
        
        scan_progress[scan_id]['status'] = 'done'
        scan_progress[scan_id]['message'] = f'Found {len(open_ports)} open ports'
        scan_progress[scan_id]['open_ports'] = open_ports
        
    except Exception as e:
        scan_progress[scan_id]['status'] = 'error'
        scan_progress[scan_id]['message'] = str(e)

def run_vuln_scan(scan_id, ip):
    """Vulnerability scan for a host"""
    scan_progress[scan_id] = {'status': 'running', 'progress': 0, 'message': f'Scanning vulnerabilities on {ip}...'}
    
    try:
        conn = db_conn()
        row = conn.execute('SELECT open_ports FROM hosts WHERE ip=?', (ip,)).fetchone()
        conn.close()
        
        if row and row['open_ports']:
            open_ports_data = json.loads(row['open_ports'])
            open_ports = {int(k): v['service'] if isinstance(v, dict) else v for k, v in open_ports_data.items()}
        else:
            # Quick scan first
            scan_progress[scan_id]['message'] = 'No port data, running quick scan first...'
            ports = list(COMMON_PORTS.keys())
            open_ports = {}
            results = scan_ports_range(ip, ports)
            open_ports = results
        
        scan_progress[scan_id]['progress'] = 50
        scan_progress[scan_id]['message'] = 'Checking vulnerabilities...'
        
        vulns = check_vulns(ip, open_ports)
        
        # Save vulns
        conn = db_conn()
        conn.execute('DELETE FROM vulnerabilities WHERE host_ip=?', (ip,))
        for v in vulns:
            conn.execute('''INSERT INTO vulnerabilities 
                (host_ip, port, service, vuln_type, severity, description, recommendation, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (v['host_ip'], v['port'], v['service'], v['vuln_type'],
                 v['severity'], v['description'], v['recommendation'], v['found_at']))
        
        score = risk_score(vulns)
        conn.execute('UPDATE hosts SET risk_score=? WHERE ip=?', (score, ip))
        conn.commit()
        conn.close()
        
        scan_progress[scan_id]['status'] = 'done'
        scan_progress[scan_id]['progress'] = 100
        scan_progress[scan_id]['message'] = f'Found {len(vulns)} vulnerabilities. Risk score: {score}'
        scan_progress[scan_id]['vulns'] = vulns
        scan_progress[scan_id]['risk_score'] = score
        
    except Exception as e:
        scan_progress[scan_id]['status'] = 'error'
        scan_progress[scan_id]['message'] = str(e)

# ─────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────

def generate_html_report():
    """Generate HTML audit report"""
    conn = db_conn()
    hosts = conn.execute('SELECT * FROM hosts ORDER BY ip').fetchall()
    vulns = conn.execute('SELECT * FROM vulnerabilities ORDER BY severity, host_ip').fetchall()
    scans = conn.execute('SELECT * FROM scans ORDER BY started_at DESC LIMIT 20').fetchall()
    conn.close()
    
    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for v in vulns:
        sev = v['severity'] if v['severity'] in sev_counts else 'INFO'
        sev_counts[sev] += 1
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Nirvana LAN - Audit Report {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; margin: 0; padding: 20px; }}
  h1 {{ color: #00d4ff; }} h2 {{ color: #7c3aed; border-bottom: 1px solid #333; padding-bottom: 8px; }}
  .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
  .CRITICAL {{ background: #7f1d1d; color: #fca5a5; }}
  .HIGH {{ background: #7c2d12; color: #fdba74; }}
  .MEDIUM {{ background: #713f12; color: #fcd34d; }}
  .LOW {{ background: #1e3a5f; color: #93c5fd; }}
  .INFO {{ background: #1e293b; color: #94a3b8; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th {{ background: #1e293b; padding: 10px; text-align: left; }}
  td {{ border-bottom: 1px solid #1e293b; padding: 10px; }}
  tr:hover {{ background: #1a1f2e; }}
  .stat {{ display: inline-block; background: #1e293b; padding: 16px 24px; border-radius: 8px; margin: 8px; text-align: center; }}
  .stat .num {{ font-size: 2em; font-weight: bold; color: #00d4ff; }}
</style>
</head>
<body>
<h1>🔍 Nirvana LAN — Security Audit Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<h2>Executive Summary</h2>
<div>
  <div class="stat"><div class="num">{len(hosts)}</div>Hosts Discovered</div>
  <div class="stat"><div class="num" style="color:#ef4444">{sev_counts['CRITICAL']}</div>Critical</div>
  <div class="stat"><div class="num" style="color:#f97316">{sev_counts['HIGH']}</div>High</div>
  <div class="stat"><div class="num" style="color:#eab308">{sev_counts['MEDIUM']}</div>Medium</div>
  <div class="stat"><div class="num" style="color:#3b82f6">{sev_counts['LOW']}</div>Low</div>
  <div class="stat"><div class="num">{len(vulns)}</div>Total Findings</div>
</div>

<h2>Discovered Hosts</h2>
<table>
<tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>OS</th><th>Risk Score</th><th>Last Seen</th></tr>
"""
    for h in hosts:
        risk = h[11] or 0
        color = '#ef4444' if risk >= 70 else '#f97316' if risk >= 40 else '#eab308' if risk >= 20 else '#22c55e'
        html += f"<tr><td>{h[1]}</td><td>{h[3] or '-'}</td><td>{h[2] or '-'}</td>"
        html += f"<td>{h[4] or '-'}</td><td>{h[5] or '-'}</td>"
        html += f"<td style='color:{color};font-weight:bold'>{risk}</td><td>{h[10] or '-'}</td></tr>\n"
    
    html += """</table>
<h2>Vulnerability Findings</h2>
<table>
<tr><th>Host</th><th>Port</th><th>Service</th><th>Type</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>
"""
    for v in vulns:
        html += f"<tr><td>{v[1]}</td><td>{v[2]}</td><td>{v[3]}</td><td>{v[4]}</td>"
        html += f"<td><span class='badge {v[5]}'>{v[5]}</span></td>"
        html += f"<td>{v[6]}</td><td>{v[7]}</td></tr>\n"
    
    html += f"""</table>
<p style="color:#555;text-align:center;margin-top:40px">Nirvana LAN Network Audit Tool — {datetime.now().year}</p>
</body></html>"""
    
    return html

def generate_txt_report():
    """Generate plain text report"""
    conn = db_conn()
    hosts = conn.execute('SELECT * FROM hosts ORDER BY ip').fetchall()
    vulns = conn.execute('SELECT * FROM vulnerabilities ORDER BY severity, host_ip').fetchall()
    conn.close()
    
    lines = [
        "=" * 70,
        f"  NIRVANA LAN - NETWORK AUDIT REPORT",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70, "",
        "DISCOVERED HOSTS",
        "-" * 70,
    ]
    for h in hosts:
        lines.append(f"  IP: {h['ip']:<18} MAC: {h['mac'] or 'N/A':<20} Host: {h['hostname'] or 'N/A'}")
        lines.append(f"  Vendor: {h['vendor'] or 'N/A':<15} OS: {h['os_guess'] or 'N/A':<20} Risk: {h['risk_score'] or 0}")
        if h['open_ports']:
            try:
                ports = json.loads(h['open_ports'])
                lines.append(f"  Open ports: {', '.join(str(p) for p in ports.keys())}")
            except:
                pass
        lines.append("")

    lines += ["", "VULNERABILITIES", "-" * 70]
    for v in vulns:
        lines.append(f"  [{v['severity']}] {v['host_ip']}:{v['port']} ({v['service']}) - {v['vuln_type']}")
        lines.append(f"  Desc: {v['description']}")
        lines.append(f"  Fix:  {v['recommendation']}")
        lines.append("")
    
    return "\n".join(lines)

# ─────────────────────────────────────────────
# FLASK ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/network-info')
def api_network_info():
    networks = get_local_networks()
    hostname = socket.gethostname()
    # Pick the best suggested network (first RFC1918 /24 or similar)
    suggested = None
    for n in networks:
        cidr = int(n['cidr'])
        if cidr <= 24:
            suggested = n['network']
            break
    if not suggested and networks:
        # If all are /25-/30, still suggest the first one
        suggested = networks[0]['network']
    return jsonify({
        'networks': networks,
        'hostname': hostname,
        'suggested': suggested
    })

@app.route('/api/hosts')
def api_hosts():
    conn = db_conn()
    rows = conn.execute('SELECT * FROM hosts ORDER BY ip').fetchall()
    conn.close()
    hosts = []
    for r in rows:
        ports = {}
        raw_ports = r['open_ports']
        if raw_ports:
            try: ports = json.loads(raw_ports)
            except: pass
        hosts.append({
            'id': r['id'], 'ip': r['ip'], 'mac': r['mac'], 'hostname': r['hostname'],
            'vendor': r['vendor'], 'os_guess': r['os_guess'], 'status': r['status'],
            'open_ports': ports, 'last_seen': r['last_seen'],
            'risk_score': r['risk_score'] or 0, 'notes': r['notes']
        })
    return jsonify(hosts)

@app.route('/api/hosts/<ip>', methods=['GET'])
def api_host_detail(ip):
    conn = db_conn()
    row = conn.execute('SELECT * FROM hosts WHERE ip=?', (ip,)).fetchone()
    vulns = conn.execute('SELECT * FROM vulnerabilities WHERE host_ip=?', (ip,)).fetchall()
    conn.close()
    if not row:
        return jsonify({'error': 'Host not found'}), 404
    ports = {}
    raw_ports = row['open_ports']
    if raw_ports:
        try: ports = json.loads(raw_ports)
        except: pass
    vuln_list = [{
        'port': v['port'], 'service': v['service'], 'vuln_type': v['vuln_type'],
        'severity': v['severity'], 'description': v['description'],
        'recommendation': v['recommendation']
    } for v in vulns]
    return jsonify({
        'ip': row['ip'], 'mac': row['mac'], 'hostname': row['hostname'],
        'vendor': row['vendor'], 'os_guess': row['os_guess'], 'status': row['status'],
        'open_ports': ports, 'last_seen': row['last_seen'],
        'risk_score': row['risk_score'] or 0, 'notes': row['notes'],
        'vulnerabilities': vuln_list
    })

@app.route('/api/hosts/<ip>/notes', methods=['POST'])
def api_update_notes(ip):
    notes = request.json.get('notes', '')
    conn = db_conn()
    conn.execute('UPDATE hosts SET notes=? WHERE ip=?', (notes, ip))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    data = request.json
    scan_type = data.get('type', 'discovery')
    target = data.get('target', '')
    options = data.get('options', {})
    
    scan_id = hashlib.md5(f"{scan_type}{target}{time.time()}".encode()).hexdigest()[:12]
    scan_progress[scan_id] = {'status': 'queued', 'progress': 0, 'started_at': datetime.now().isoformat()}
    
    if scan_type == 'discovery':
        t = threading.Thread(target=run_discovery_scan, args=(scan_id, target, options))
    elif scan_type == 'ports':
        port_range = data.get('port_range', 'common')
        t = threading.Thread(target=run_port_scan, args=(scan_id, target, port_range))
    elif scan_type == 'vulns':
        t = threading.Thread(target=run_vuln_scan, args=(scan_id, target))
    elif scan_type == 'dns':
        def dns_task():
            scan_progress[scan_id]['status'] = 'running'
            results = dns_enum(target)
            scan_progress[scan_id]['status'] = 'done'
            scan_progress[scan_id]['progress'] = 100
            scan_progress[scan_id]['results'] = results
        t = threading.Thread(target=dns_task)
    elif scan_type == 'smb':
        def smb_task():
            scan_progress[scan_id]['status'] = 'running'
            results = smb_enum(target)
            scan_progress[scan_id]['status'] = 'done'
            scan_progress[scan_id]['progress'] = 100
            scan_progress[scan_id]['results'] = results
        t = threading.Thread(target=smb_task)
    else:
        return jsonify({'error': 'Unknown scan type'}), 400
    
    t.daemon = True
    t.start()
    return jsonify({'scan_id': scan_id})

@app.route('/api/scan/status/<scan_id>')
def api_scan_status(scan_id):
    return jsonify(scan_progress.get(scan_id, {'status': 'not_found'}))

@app.route('/api/vulnerabilities')
def api_vulns():
    conn = db_conn()
    rows = conn.execute('SELECT * FROM vulnerabilities ORDER BY severity, host_ip').fetchall()
    conn.close()
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    vulns = [{'id': r['id'], 'host_ip': r['host_ip'], 'port': r['port'], 'service': r['service'],
               'vuln_type': r['vuln_type'], 'severity': r['severity'], 'description': r['description'],
               'recommendation': r['recommendation'], 'found_at': r['found_at']} for r in rows]
    vulns.sort(key=lambda x: severity_order.get(x['severity'], 5))
    return jsonify(vulns)

@app.route('/api/stats')
def api_stats():
    conn = db_conn()
    total_hosts = conn.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
    up_hosts = conn.execute("SELECT COUNT(*) FROM hosts WHERE status='up'").fetchone()[0]
    total_vulns = conn.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
    crit = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity='CRITICAL'").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity='HIGH'").fetchone()[0]
    med = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity='MEDIUM'").fetchone()[0]
    low = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity='LOW'").fetchone()[0]
    recent_scans = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    
    # Port distribution
    hosts_with_ports = conn.execute("SELECT open_ports FROM hosts WHERE open_ports IS NOT NULL AND open_ports != ''").fetchall()
    port_counts = {}
    for row in hosts_with_ports:
        try:
            ports = json.loads(row['open_ports'])
            for p in ports:
                port_counts[str(p)] = port_counts.get(str(p), 0) + 1
        except: pass
    
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    conn.close()
    
    return jsonify({
        'total_hosts': total_hosts, 'up_hosts': up_hosts,
        'total_vulns': total_vulns, 'critical': crit, 'high': high,
        'medium': med, 'low': low, 'scans': recent_scans,
        'top_ports': [{'port': int(p), 'service': COMMON_PORTS.get(int(p), 'unknown'), 'count': c} for p, c in top_ports]
    })

@app.route('/api/report/html')
def api_report_html():
    html = generate_html_report()
    buf = io.BytesIO(html.encode('utf-8'))
    buf.seek(0)
    return send_file(buf, mimetype='text/html',
                     download_name=f'nirvana_lan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html',
                     as_attachment=True)

@app.route('/api/report/txt')
def api_report_txt():
    txt = generate_txt_report()
    buf = io.BytesIO(txt.encode('utf-8'))
    buf.seek(0)
    return send_file(buf, mimetype='text/plain',
                     download_name=f'nirvana_lan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt',
                     as_attachment=True)

@app.route('/api/hosts/clear', methods=['POST'])
def api_clear_hosts():
    conn = db_conn()
    conn.execute('DELETE FROM hosts')
    conn.execute('DELETE FROM vulnerabilities')
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/scheduled', methods=['GET'])
def api_get_scheduled():
    conn = db_conn()
    rows = conn.execute('SELECT * FROM scheduled_tasks').fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'], 'name': r['name'], 'scan_type': r['scan_type'], 'target': r['target'],
        'schedule': r['schedule'], 'last_run': r['last_run'], 'next_run': r['next_run'], 'enabled': r['enabled']
    } for r in rows])

@app.route('/api/scheduled', methods=['POST'])
def api_add_scheduled():
    data = request.json
    conn = db_conn()
    conn.execute('''INSERT INTO scheduled_tasks (name, scan_type, target, schedule, enabled)
        VALUES (?, ?, ?, ?, 1)''',
        (data['name'], data['scan_type'], data['target'], data['schedule']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/scheduled/<int:task_id>', methods=['DELETE'])
def api_del_scheduled(task_id):
    conn = db_conn()
    conn.execute('DELETE FROM scheduled_tasks WHERE id=?', (task_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    port = 7777
    print(f"\n{'='*50}")
    print(f"  🔍 NIRVANA LAN - Network Audit Tool")
    print(f"{'='*50}")
    print(f"  Open: http://localhost:{port}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*50}\n")
    
    # Auto-open browser after 1.5 seconds
    def open_browser():
        time.sleep(1.5)
        webbrowser.open(f'http://localhost:{port}')
    threading.Thread(target=open_browser, daemon=True).start()
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
