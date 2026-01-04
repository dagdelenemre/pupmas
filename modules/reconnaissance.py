#!/usr/bin/env python3
"""
Advanced Reconnaissance Module
Complete scanning and enumeration without external tools
"""

import socket
import subprocess
import threading
import json
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import ipaddress
import dns.resolver
import dns.rdatatype
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class PortInfo:
    """Port information"""
    port: int
    protocol: str
    state: str  # open, closed, filtered
    service: str = ""
    version: str = ""
    banner: str = ""
    cves: List[str] = field(default_factory=list)

@dataclass
class HostInfo:
    """Host scan results"""
    target: str
    ip: str = ""
    alive: bool = False
    open_ports: List[PortInfo] = field(default_factory=list)
    os_guess: str = ""
    services: Dict[str, str] = field(default_factory=dict)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    subdomain: List[str] = field(default_factory=list)
    subdomain_ports: Dict[str, List[PortInfo]] = field(default_factory=dict)
    http_title: str = ""
    is_vulnerable: bool = False
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

class ReconnaissanceEngine:
    """Advanced reconnaissance without nmap dependency"""
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5984: "CouchDB", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        9200: "Elasticsearch", 27017: "MongoDB", 3000: "Node.js",
        465: "SMTPS", 587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S",
        2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL",
        2095: "Webmail", 2096: "Webmail-SSL"
    }
    
    def __init__(self):
        self.scan_results = {}
        self.dns_server = "8.8.8.8"
        
    def is_valid_target(self, target: str) -> bool:
        """Check if target is valid IP or domain"""
        # Try IP
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Try domain
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False
    
    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    def scan_port(self, host: str, port: int, timeout: float = 0.5) -> Tuple[int, bool]:
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port, result == 0
        except Exception:
            return port, False
    
    def scan_ports(self, host: str, ports: List[int] = None, timeout: float = 0.5) -> List[PortInfo]:
        """Scan multiple ports in parallel"""
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(self.scan_port, host, port, timeout): port 
                for port in ports
            }
            
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    service_name = self.COMMON_PORTS.get(port, "Unknown")
                    banner = self.grab_banner(host, port)
                    
                    open_ports.append(PortInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=service_name,
                        banner=banner
                    ))
        
        return sorted(open_ports, key=lambda x: x.port)
    
    def grab_banner(self, host: str, port: int, timeout: float = 2.0) -> str:
        """Grab service banner"""
        try:
            # Try HTTP GET/HEAD request for web ports - get Server header
            http_like_ports = {80, 443, 8080, 8443, 8000, 8888, 2082, 2083, 2086, 2087, 2095, 2096}
            https_ports = {443, 8443, 2083, 2087, 2096}
            if port in http_like_ports:
                import requests
                import urllib3
                urllib3.disable_warnings()
                protocol = "https" if port in https_ports else "http"
                try:
                    # Direct IP connection, use domain in Host header
                    response = requests.get(
                        f"{protocol}://{host}:{port}", 
                        timeout=5, 
                        verify=False,
                        allow_redirects=False
                    )
                    server = response.headers.get('Server', '') or response.headers.get('server', '')
                    powered_by = response.headers.get('X-Powered-By', '') or response.headers.get('x-powered-by', '')
                    
                    banner_parts = []
                    if server:
                        banner_parts.append(server)
                    if powered_by:
                        banner_parts.append(powered_by)
                    
                    if banner_parts:
                        return " | ".join(banner_parts)
                except Exception as e:
                    pass
            # TLS-only banners (mail/secure ports)
            tls_banner_ports = {465, 993, 995}
            if port in tls_banner_ports:
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            ssock.settimeout(timeout)
                            try:
                                data = ssock.recv(2048).decode('utf-8', errors='ignore')
                                if data:
                                    first_line = data.split('\n')[0].strip()
                                    if first_line:
                                        return first_line[:200]
                            except socket.timeout:
                                pass
                            try:
                                ssock.sendall(b"\r\n")
                                data = ssock.recv(2048).decode('utf-8', errors='ignore')
                                if data:
                                    return data.split('\n')[0][:200]
                            except Exception:
                                pass
                except Exception:
                    pass
            
            # Try socket banner grab
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send HTTP request for web ports
            if port in [80, 8080, 8000, 8888, 8443, 443]:
                sock.send(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
                time.sleep(0.2)
            
            banner = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            
            # Extract Server header from HTTP response
            if 'HTTP' in banner:
                for line in banner.split('\r\n'):
                    if line.lower().startswith('server:'):
                        return line.split(':', 1)[1].strip()[:200]
            
            return banner.split('\n')[0][:200] if banner else ""
        except Exception:
            return ""

    def _is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to Cloudflare ranges"""
        cf_ranges = [
            '173.245.48.', '103.21.244.', '103.22.200.', '103.31.4.',
            '141.101.64.', '108.162.192.', '190.93.240.', '188.114.96.',
            '197.234.240.', '198.41.128.', '162.158.', '104.16.',
            '172.64.', '131.0.72.', '104.17.', '104.18.', '104.19.',
            '104.20.', '104.21.', '104.22.', '104.23.', '104.24.',
            '104.25.', '104.26.', '104.27.', '104.28.', '104.29.',
            '104.30.', '104.31.'
        ]
        return any(ip.startswith(prefix) for prefix in cf_ranges)
    
    def detect_service_version(self, host: str, port: int, banner: str) -> Tuple[str, List[str]]:
        """Detect service version and potential CVEs"""
        cves = []
        
        # Service detection patterns
        patterns = {
            "Apache": {
                "pattern": r"Apache/(\d+\.\d+\.\d+)",
                "cve_prefix": "Apache"
            },
            "Nginx": {
                "pattern": r"nginx/(\d+\.\d+\.\d+)",
                "cve_prefix": "Nginx"
            },
            "OpenSSH": {
                "pattern": r"OpenSSH[_\-](\d+\.\d+)",
                "cve_prefix": "OpenSSH"
            },
            "MySQL": {
                "pattern": r"MySQL[_\-](\d+\.\d+\.\d+)",
                "cve_prefix": "MySQL"
            },
            "PostgreSQL": {
                "pattern": r"PostgreSQL[_\-](\d+\.\d+)",
                "cve_prefix": "PostgreSQL"
            },
            "FTP": {
                "pattern": r"vsftpd[_\-](\d+\.\d+\.\d+)",
                "cve_prefix": "vsftpd"
            }
        }
        
        version_info = ""
        for service, config in patterns.items():
            import re
            match = re.search(config["pattern"], banner)
            if match:
                version_info = f"{service} {match.group(1)}"
                # Common CVEs mapping
                common_vulns = {
                    "Apache": ["CVE-2021-41773", "CVE-2024-50379"],
                    "Nginx": ["CVE-2017-7529", "CVE-2021-23017"],
                    "OpenSSH": ["CVE-2023-28617", "CVE-2024-6387"],
                    "MySQL": ["CVE-2021-22911", "CVE-2024-20981"],
                    "PostgreSQL": ["CVE-2023-39417", "CVE-2024-4317"],
                    "vsftpd": ["CVE-2011-2523"]
                }
                cves = common_vulns.get(service, [])
                break
        
        return version_info, cves
    
    def dns_enumeration(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records"""
        records = {
            "A": [], "AAAA": [], "MX": [],
            "NS": [], "TXT": [], "CNAME": []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            
            for record_type in records.keys():
                try:
                    answers = resolver.resolve(domain, record_type)
                    for answer in answers:
                        records[record_type].append(str(answer))
                except Exception:
                    pass
        except Exception:
            pass
        
        return {k: v for k, v in records.items() if v}
    
    def subdomain_enumeration(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """Enumerate subdomains"""
        if wordlist is None:
            wordlist = [
                "www", "mail", "ftp", "admin", "api", "dev", "test",
                "staging", "prod", "backup", "db", "sql", "api-v1",
                "cdn", "vpn", "docker", "jenkins", "git", "svn"
            ]
        
        subdomains = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._check_subdomain, f"{sub}.{domain}"): sub
                for sub in wordlist
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)
        
        return subdomains
    
    def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if subdomain exists"""
        try:
            ip = socket.gethostbyname(subdomain)
            return f"{subdomain} ({ip})"
        except socket.gaierror:
            return None
    
    def check_http_service(self, host: str, port: int = 80, ssl: bool = False) -> Optional[str]:
        """Check HTTP service and grab title"""
        try:
            import urllib.request
            protocol = "https" if ssl else "http"
            url = f"{protocol}://{host}:{port}/"
            
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'
            })
            
            response = urllib.request.urlopen(req, timeout=5)
            html = response.read().decode('utf-8', errors='ignore')
            
            # Extract title
            import re
            title_match = re.search(r'<title>(.*?)</title>', html)
            if title_match:
                return title_match.group(1)
        except Exception:
            pass
        
        return None
    
    def full_scan(self, target: str, profile: str = "active") -> HostInfo:
        """
        Full reconnaissance scan
        profile: 'passive', 'active', 'aggressive'
        """
        from utils.helpers import print_info, print_success
        
        host_info = HostInfo(target=target)
        
        # Resolve hostname
        print_info(f"[*] Resolving {target}...")
        ip = self.resolve_hostname(target)
        if not ip:
            return host_info
        
        host_info.ip = ip
        host_info.alive = True
        
        # Port scanning
        ports_to_scan: List[int] = []
        if profile in ["active", "aggressive"]:
            print_info(f"[*] Scanning ports on {ip}...")
            ports = list(self.COMMON_PORTS.keys())
            if profile == "aggressive":
                # Top 100 most common ports for speed
                ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
                        20, 69, 161, 162, 389, 636, 1433, 1434, 5432, 5984, 6379, 8443, 9200, 27017,
                        137, 138, 548, 8888, 8000, 5000, 3000, 9090, 9999, 8008, 81, 82, 83, 8081, 8082,
                        123, 179, 445, 500, 514, 515, 587, 631, 873, 902, 1080, 1194, 1352, 1433, 1521,
                        2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 3128, 4443, 4444, 5001, 5222, 5269,
                        5357, 5432, 5500, 5800, 5801, 5900, 6000, 6001, 6379, 6666, 7000, 7001, 7777, 8009,
                        8089, 8090, 8180, 8888, 9000, 9001, 9080, 9090, 9100, 9999, 10000, 10443, 11211, 27017]
            ports_to_scan = ports
            
            host_info.open_ports = self.scan_ports(ip, ports)
            print_success(f"[+] Found {len(host_info.open_ports)} open ports")
            
            # Service detection
            print_info("[*] Detecting services...")
            for port_info in host_info.open_ports:
                version, cves = self.detect_service_version(
                    ip, port_info.port, port_info.banner
                )
                port_info.version = version
                port_info.cves = cves
                host_info.services[port_info.service] = version
                
                # Check HTTP
                if port_info.port in [80, 8080, 443, 8443]:
                    ssl = port_info.port in [443, 8443]
                    title = self.check_http_service(ip, port_info.port, ssl)
                    if title:
                        host_info.http_title = title
        
        # DNS enumeration
        print_info("[*] Enumerating DNS records...")
        host_info.dns_records = self.dns_enumeration(target)
        
        if profile in ["active", "aggressive"]:
            print_info("[*] Enumerating subdomains...")
            host_info.subdomain = self.subdomain_enumeration(target)
            print_success(f"[+] Found {len(host_info.subdomain)} subdomains")
            if host_info.subdomain:
                host_info.subdomain_ports = self._scan_subdomain_ports(host_info.subdomain, ports_to_scan or list(self.COMMON_PORTS.keys()))
        
        # Vulnerability check
        if host_info.open_ports:
            cve_count = sum(len(p.cves) for p in host_info.open_ports)
            if cve_count > 0:
                host_info.is_vulnerable = True
                print_success(f"[+] Found {cve_count} potential CVEs")
        
        return host_info

    def _scan_subdomain_ports(self, subdomains: List[str], ports: List[int]) -> Dict[str, List[PortInfo]]:
        """Scan ports for subdomains that are not on Cloudflare"""
        from utils.helpers import print_info, print_success
        results: Dict[str, List[PortInfo]] = {}
        for subdomain_entry in subdomains:
            if '(' in subdomain_entry and ')' in subdomain_entry:
                subdomain = subdomain_entry.split('(')[0].strip()
                ip = subdomain_entry.split('(')[1].rstrip(')')
            else:
                subdomain = subdomain_entry.strip()
                ip = None
            if not ip or self._is_cloudflare_ip(ip):
                continue
            print_info(f"[*] Scanning non-CDN subdomain {subdomain} ({ip})...")
            sub_ports = self.scan_ports(ip, ports)
            results[subdomain_entry] = sub_ports
            print_success(f"[+] {subdomain}: {len(sub_ports)} open ports (non-CDN)")
        return results
    
    def export_results(self, host_info: HostInfo, output_file: str = "recon_results.json"):
        """Export scan results"""
        # Convert dataclasses to dict
        data = {
            "target": host_info.target,
            "ip": host_info.ip,
            "alive": host_info.alive,
            "http_title": host_info.http_title,
            "is_vulnerable": host_info.is_vulnerable,
            "scan_timestamp": host_info.scan_timestamp,
            "open_ports": [asdict(p) for p in host_info.open_ports],
            "services": host_info.services,
            "dns_records": host_info.dns_records,
            "subdomains": host_info.subdomain,
            "subdomain_ports": {
                sub: [asdict(p) for p in ports]
                for sub, ports in host_info.subdomain_ports.items()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        return output_file
