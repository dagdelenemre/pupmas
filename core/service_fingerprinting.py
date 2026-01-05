#!/usr/bin/env python3
"""
Service Fingerprinting Module - Real Service Detection & Version Identification
Banner grabbing, HTTP headers, version extraction, CVE mapping with confidence scoring
"""

import socket
import subprocess
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import requests
from urllib.parse import urlparse


@dataclass
class ServiceInfo:
    """Detected service information"""
    host: str
    port: int
    protocol: str  # TCP/UDP
    service_name: str = ""
    version: str = ""
    product: str = ""  # e.g., "OpenSSH", "Apache", "Nginx"
    banner: str = ""
    http_title: str = ""
    http_server_header: str = ""
    cpe: str = ""  # Common Platform Enumeration
    confidence: float = 0.0  # 0.0-1.0
    vulnerable_cves: List[str] = None
    evidence: Dict = None
    
    def __post_init__(self):
        if self.vulnerable_cves is None:
            self.vulnerable_cves = []
        if self.evidence is None:
            self.evidence = {}


class ServiceFingerprinter:
    """Advanced service detection and version fingerprinting"""
    
    # Known service ports
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5984: "CouchDB",
        6379: "Redis",
        7001: "Cassandra",
        8000: "HTTP-Alt",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
        50070: "Hadoop",
    }
    
    # CVE vulnerability database (simplified)
    CVE_DATABASE = {
        "OpenSSH": {
            "5.1": ["CVE-2008-4109"],
            "6.9": ["CVE-2015-4000"],
            "7.4": ["CVE-2018-15473"],
            "9.3": ["CVE-2024-6387"],  # regreSSHion
        },
        "Apache": {
            "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
            "2.4.50": ["CVE-2021-42013"],
        },
        "Nginx": {
            "1.16.0": ["CVE-2019-9511"],
        },
        "MySQL": {
            "5.7.0": ["CVE-2019-2628", "CVE-2019-2725"],
            "8.0.0": ["CVE-2021-2109"],
        },
        "PostgreSQL": {
            "12.0": ["CVE-2019-10130"],
            "13.0": ["CVE-2021-3393"],
        },
        "Redis": {
            "5.0.0": ["CVE-2019-11735"],
            "6.0.0": ["CVE-2020-14147"],
        },
        "MongoDB": {
            "3.6.0": ["CVE-2019-2725"],
            "4.0.0": ["CVE-2019-12840"],
        },
    }
    
    def __init__(self):
        self.detected_services = {}
        self.timeouts = {"socket": 3, "http": 5}
    
    def scan_host(self, host: str, ports: Optional[List[int]] = None) -> List[ServiceInfo]:
        """Scan host for services on specific ports"""
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        services = []
        for port in ports:
            service = self._probe_port(host, port)
            if service:
                services.append(service)
        
        return services
    
    def _probe_port(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Probe single port for service information"""
        # Pre-flight: check if port is open
        if not self._is_port_open(host, port):
            return None
        
        service_name = self.COMMON_PORTS.get(port, "Unknown")
        service = ServiceInfo(host=host, port=port, protocol="TCP", service_name=service_name)
        
        # Try banner grabbing
        banner = self._grab_banner(host, port)
        if banner:
            service.banner = banner
            service.evidence['banner'] = banner
        
        # HTTP-based detection (80, 443, 8080, 8443)
        if port in [80, 443, 8080, 8443]:
            http_info = self._probe_http(host, port, use_https=(port in [443, 8443]))
            if http_info:
                service.http_title = http_info.get('title', '')
                service.http_server_header = http_info.get('server', '')
                service.evidence['http_server_header'] = http_info.get('server', '')
                service.evidence['http_title'] = http_info.get('title', '')
                
                # Extract version from HTTP headers
                if 'server' in http_info:
                    service = self._extract_version_from_banner(service, http_info['server'])
        
        # SSH detection (port 22)
        elif port == 22 and service.banner:
            service = self._extract_ssh_version(service)
        
        # MySQL detection (port 3306)
        elif port == 3306 and service.banner:
            service = self._extract_mysql_version(service)
        
        # PostgreSQL detection (port 5432)
        elif port == 5432 and service.banner:
            service = self._extract_postgres_version(service)
        
        # Redis detection (port 6379)
        elif port == 6379 and service.banner:
            service = self._extract_redis_version(service)
        
        # Calculate confidence and map to CVEs
        if service.product:
            service.confidence = 0.9 if service.version else 0.6
            service.vulnerable_cves = self._lookup_cves(service.product, service.version)
        else:
            service.confidence = 0.3  # Low confidence if no product identified
        
        return service if service.confidence > 0.3 else None
    
    def _is_port_open(self, host: str, port: int, timeout: int = 2) -> bool:
        """Quick port check"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeouts['socket'])
            sock.connect((host, port))
            
            # Send trigger for some services
            if port == 25:  # SMTP
                sock.send(b"EHLO localhost\r\n")
            elif port == 110:  # POP3
                sock.send(b"USER\r\n")
            elif port == 143:  # IMAP
                sock.send(b"CAPABILITY\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner if banner else None
        except Exception:
            return None
    
    def _probe_http(self, host: str, port: int, use_https: bool = False) -> Optional[Dict]:
        """Probe HTTP service for headers and title"""
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{host}:{port}" if port not in [80, 443] else f"{scheme}://{host}"
        
        try:
            resp = requests.get(url, timeout=self.timeouts['http'], verify=False, allow_redirects=False)
            
            # Extract title
            title = ""
            if "<title>" in resp.text.lower():
                match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.IGNORECASE)
                if match:
                    title = match.group(1).strip()
            
            return {
                'server': resp.headers.get('Server', ''),
                'title': title,
                'status': resp.status_code,
                'headers': dict(resp.headers)
            }
        except Exception:
            return None
    
    def _extract_ssh_version(self, service: ServiceInfo) -> ServiceInfo:
        """Extract SSH version from banner"""
        # Format: SSH-2.0-OpenSSH_7.4
        match = re.search(r'OpenSSH[_\s]+([0-9\.p]+)', service.banner, re.IGNORECASE)
        if match:
            service.product = "OpenSSH"
            service.version = match.group(1)
            service.cpe = f"cpe:/a:openbsd:openssh:{service.version}"
            return service
        
        # Fallback: just mark as SSH
        service.product = "SSH"
        service.confidence = 0.5
        return service
    
    def _extract_mysql_version(self, service: ServiceInfo) -> ServiceInfo:
        """Extract MySQL version from banner"""
        match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', service.banner)
        if match:
            service.product = "MySQL"
            service.version = match.group(1)
            service.cpe = f"cpe:/a:mysql:mysql:{service.version}"
            return service
        
        service.product = "MySQL"
        service.confidence = 0.6
        return service
    
    def _extract_postgres_version(self, service: ServiceInfo) -> ServiceInfo:
        """Extract PostgreSQL version from banner"""
        match = re.search(r'([0-9]+\.[0-9]+)', service.banner)
        if match:
            service.product = "PostgreSQL"
            service.version = match.group(1)
            service.cpe = f"cpe:/a:postgresql:postgresql:{service.version}"
            return service
        
        service.product = "PostgreSQL"
        service.confidence = 0.6
        return service
    
    def _extract_redis_version(self, service: ServiceInfo) -> ServiceInfo:
        """Extract Redis version from banner"""
        match = re.search(r'redis_version:([0-9\.]+)', service.banner)
        if match:
            service.product = "Redis"
            service.version = match.group(1)
            service.cpe = f"cpe:/a:redis:redis:{service.version}"
            return service
        
        service.product = "Redis"
        service.confidence = 0.6
        return service
    
    def _extract_version_from_banner(self, service: ServiceInfo, banner: str) -> ServiceInfo:
        """Extract version from HTTP Server header or other banners"""
        
        # Apache
        match = re.search(r'Apache[/\s]+([0-9\.]+)', banner, re.IGNORECASE)
        if match:
            service.product = "Apache"
            service.version = match.group(1)
            service.cpe = f"cpe:/a:apache:http_server:{service.version}"
            return service
        
        # Nginx
        match = re.search(r'nginx[/\s]+([0-9\.]+)', banner, re.IGNORECASE)
        if match:
            service.product = "Nginx"
            service.version = match.group(1)
            service.cpe = f"cpe:/a:nginx:nginx:{service.version}"
            return service
        
        # IIS
        match = re.search(r'IIS[/\s]+([0-9\.]+)', banner, re.IGNORECASE)
        if match:
            service.product = "IIS"
            service.version = match.group(1)
            return service
        
        # Generic
        service.product = banner.split('/')[0] if '/' in banner else banner
        if '/' in banner:
            service.version = banner.split('/')[1]
        
        service.confidence = 0.5
        return service
    
    def _lookup_cves(self, product: str, version: str) -> List[str]:
        """Look up CVEs for product version"""
        cves = []
        
        if product not in self.CVE_DATABASE:
            return cves
        
        product_cves = self.CVE_DATABASE[product]
        
        # Exact version match
        if version in product_cves:
            cves.extend(product_cves[version])
        
        # Major.minor match for older versions
        elif version:
            major_minor = '.'.join(version.split('.')[:2])
            for db_version, db_cves in product_cves.items():
                if db_version.startswith(major_minor):
                    cves.extend(db_cves)
        
        return list(set(cves))  # Deduplicate
    
    def fingerprint_to_cpe(self, service: ServiceInfo) -> str:
        """Convert service info to CPE string"""
        if service.cpe:
            return service.cpe
        
        if not service.product:
            return ""
        
        product_lower = service.product.lower()
        version = service.version or "*"
        
        return f"cpe:/a:{product_lower}:{product_lower}:{version}"


class ConfidenceCalculator:
    """Calculate confidence score for findings"""
    
    @staticmethod
    def calculate_confidence(evidence_weight: Dict[str, float]) -> float:
        """
        Calculate confidence based on evidence weight
        
        Evidence types:
        - banner: 0.9 (very strong)
        - http_header: 0.8 (strong)
        - version_match: 0.85 (strong)
        - port_inference: 0.4 (weak)
        - http_title: 0.3 (very weak)
        """
        if not evidence_weight:
            return 0.0
        
        total_weight = sum(evidence_weight.values())
        return min(1.0, total_weight / len(evidence_weight))
    
    @staticmethod
    def cve_is_applicable(cve: str, service: ServiceInfo, threshold: float = 0.7) -> Tuple[bool, float]:
        """
        Determine if CVE is applicable to service
        Returns: (is_applicable, confidence_score)
        """
        if service.confidence < threshold:
            return False, service.confidence
        
        return True, service.confidence
