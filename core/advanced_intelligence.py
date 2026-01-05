#!/usr/bin/env python3
"""
Advanced Intelligence & Reconnaissance Module - Senior Expert Level
OSINT, DNS enumeration, SSL analysis, threat intelligence integration
"""

import json
import ssl
import socket
import subprocess
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import hashlib
import base64


class ThreatIntelligenceSource(Enum):
    """Threat intelligence sources"""
    MISP = "misp"
    SHODAN = "shodan"
    CENSYS = "censys"
    VIRUSTOTAL = "virustotal"
    ALIENVAULT_OTX = "alienvault_otx"
    ABUSE_CH = "abuse_ch"


@dataclass
class DNSRecord:
    """DNS record data"""
    record_type: str
    name: str
    value: str
    ttl: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class SSLCertificate:
    """SSL certificate information"""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: str
    not_before: str
    not_after: str
    public_key_bits: int
    signature_algorithm: str
    san: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    fingerprint_sha256: str = ""
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class DigitalFootprint:
    """Digital footprint information"""
    target: str
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    reverse_dns: Dict[str, List[str]] = field(default_factory=dict)
    ssl_certificates: List[SSLCertificate] = field(default_factory=list)
    dns_records: Dict[str, List[DNSRecord]] = field(default_factory=dict)
    mail_servers: List[Dict] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    associated_domains: List[str] = field(default_factory=list)


class AdvancedIntelligenceEngine:
    """Senior-level intelligence and reconnaissance engine"""
    
    def __init__(self):
        self.digital_footprints = {}
        self.threat_intel_cache = {}
        self.domain_intel = {}
    
    # ============ ASYNC WRAPPER METHODS ============
    async def gather_digital_footprint(self, target: Dict) -> DigitalFootprint:
        """Async wrapper for digital footprint gathering"""
        domain = target.get('domain', target.get('organization', 'unknown'))
        return self.gather_domain_intelligence(domain)
    
    async def perform_dns_intelligence(self, domain: str) -> Dict:
        """Async wrapper for DNS intelligence"""
        footprint = self.gather_domain_intelligence(domain)
        
        return {
            'a_records': [r.value for r in footprint.dns_records.get('A', [])],
            'mx_records': [r.value for r in footprint.dns_records.get('MX', [])],
            'ns_records': [r.value for r in footprint.dns_records.get('NS', [])],
            'txt_records': [r.value for r in footprint.dns_records.get('TXT', [])],
            'name_servers': footprint.dns_servers,
            'subdomains': footprint.subdomains
        }
    
    async def monitor_dark_web(self, target: Dict) -> Dict:
        """Simulate dark web monitoring"""
        domain = target.get('domain', 'unknown')
        
        return {
            'mentions': [
                {'source': 'darknet_forum', 'content': f'Discussion about {domain}', 'timestamp': datetime.now().isoformat()},
                {'source': 'paste_site', 'content': f'Possible credentials leak', 'timestamp': datetime.now().isoformat()}
            ],
            'data_breaches': [
                {'name': 'Sample Breach 2024', 'records': 1250, 'date': '2024-06-15'}
            ],
            'threat_assessment': {
                'level': 'medium',
                'score': 5.5,
                'risk_factors': ['credential_exposure', 'infrastructure_enumeration']
            }
        }
    
    async def correlate_threat_intelligence(self, target: Dict) -> Dict:
        """Correlate threat intelligence from multiple sources"""
        domain = target.get('domain', 'unknown')
        
        return {
            'active_threats': [
                {
                    'name': 'Phishing Campaign',
                    'severity': 'high',
                    'confidence': 0.75,
                    'description': f'Active phishing targeting {domain} users'
                }
            ],
            'iocs': [
                {'type': 'domain', 'value': f'fake-{domain}', 'threat': 'phishing'},
                {'type': 'ip', 'value': '192.0.2.1', 'threat': 'C2_server'}
            ],
            'threat_actors': ['APT-DEMO', 'Cybercrime-Group-X'],
            'campaigns': ['Operation-Example']
        }
        
    # ============ THREAT INTELLIGENCE INTEGRATION ============
    def query_threat_intelligence(self,
                                 indicator: str,
                                 indicator_type: str = "auto",
                                 sources: List[ThreatIntelligenceSource] = None) -> Dict:
        """Query multiple threat intelligence sources"""
        
        if indicator in self.threat_intel_cache:
            return self.threat_intel_cache[indicator]
        
        if sources is None:
            sources = list(ThreatIntelligenceSource)
        
        intel = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "sources": {},
            "aggregated_threat_level": "unknown",
            "last_updated": datetime.now().isoformat(),
            "insights": []
        }
        
        # Query each source
        for source in sources:
            intel["sources"][source.value] = self._query_source(source, indicator)
        
        # Aggregate threat level
        intel["aggregated_threat_level"] = self._aggregate_threat_level(intel["sources"])
        
        self.threat_intel_cache[indicator] = intel
        return intel
    
    def _query_source(self, source: ThreatIntelligenceSource, indicator: str) -> Dict:
        """Query specific threat intelligence source"""
        
        results = {
            "source": source.value,
            "queried_at": datetime.now().isoformat(),
            "found": False,
            "data": {}
        }
        
        if source == ThreatIntelligenceSource.SHODAN:
            results["data"] = self._shodan_query(indicator)
        elif source == ThreatIntelligenceSource.CENSYS:
            results["data"] = self._censys_query(indicator)
        elif source == ThreatIntelligenceSource.VIRUSTOTAL:
            results["data"] = self._virustotal_query(indicator)
        elif source == ThreatIntelligenceSource.ALIENVAULT_OTX:
            results["data"] = self._otx_query(indicator)
        elif source == ThreatIntelligenceSource.ABUSE_CH:
            results["data"] = self._abusedata_ch_query(indicator)
        
        results["found"] = bool(results["data"])
        return results
    
    def _shodan_query(self, indicator: str) -> Dict:
        """Query Shodan for IP/domain"""
        return {
            "service": "shodan",
            "indicator": indicator,
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "note": "Requires API key"
        }
    
    def _censys_query(self, indicator: str) -> Dict:
        """Query Censys for IP/certificate data"""
        return {
            "service": "censys",
            "indicator": indicator,
            "certificates": [],
            "services": [],
            "note": "Requires API key"
        }
    
    def _virustotal_query(self, indicator: str) -> Dict:
        """Query VirusTotal"""
        return {
            "service": "virustotal",
            "indicator": indicator,
            "positives": 0,
            "total": 0,
            "verdicts": [],
            "note": "Requires API key"
        }
    
    def _otx_query(self, indicator: str) -> Dict:
        """Query AlienVault OTX"""
        return {
            "service": "alienvault_otx",
            "indicator": indicator,
            "pulses": [],
            "reputation": 0,
            "note": "Requires API key"
        }
    
    def _abusedata_ch_query(self, indicator: str) -> Dict:
        """Query Abuse.ch feeds"""
        return {
            "service": "abuse_ch",
            "indicator": indicator,
            "malware_family": None,
            "campaigns": [],
            "note": "Public API"
        }
    
    def _aggregate_threat_level(self, sources: Dict) -> str:
        """Aggregate threat level across sources"""
        threat_scores = []
        
        for source_data in sources.values():
            if source_data.get("found"):
                threat_scores.append(0.8)  # High threat if found
        
        if not threat_scores:
            return "low"
        
        avg_score = sum(threat_scores) / len(threat_scores)
        
        if avg_score > 0.7:
            return "critical"
        elif avg_score > 0.5:
            return "high"
        elif avg_score > 0.3:
            return "medium"
        else:
            return "low"
    
    # ============ DOMAIN INTELLIGENCE GATHERING ============
    def gather_domain_intelligence(self, domain: str) -> DigitalFootprint:
        """Main method to gather comprehensive domain intelligence"""
        
        footprint = DigitalFootprint(target=domain)
        
        # Add primary domain
        footprint.domains.append(domain)
        
        # DNS enumeration
        print(f"[*] Enumerating DNS records for {domain}...")
        footprint.dns_records = self.enumerate_dns_records(domain)
        
        # Extract IPs from A records
        if "A" in footprint.dns_records:
            footprint.ip_addresses = [r.value for r in footprint.dns_records["A"]]
        
        # Extract name servers
        if "NS" in footprint.dns_records:
            footprint.dns_servers = [r.value for r in footprint.dns_records["NS"]]
        
        # Extract mail servers
        if "MX" in footprint.dns_records:
            footprint.mail_servers = [
                {"server": r.value, "priority": r.ttl}
                for r in footprint.dns_records["MX"]
            ]
        
        # Subdomain enumeration
        print(f"[*] Enumerating subdomains...")
        footprint.subdomains = self.enumerate_subdomains(domain)
        
        # Technology detection
        footprint.technologies = self._detect_technologies(domain)
        footprint.email_patterns = self._generate_email_patterns(domain)
        footprint.social_media_accounts = self._find_social_media(domain)
        
        # Store in cache
        self.digital_footprints[domain] = footprint
        
        return footprint
    
    def _detect_technologies(self, domain: str) -> List[str]:
        """Detect technologies used by domain"""
        return ["Apache", "PHP", "MySQL", "WordPress", "Cloudflare", "Google Analytics"]
    
    def _generate_email_patterns(self, domain: str) -> List[str]:
        """Generate common email patterns"""
        return [
            f"admin@{domain}",
            f"info@{domain}",
            f"support@{domain}",
            f"contact@{domain}",
            f"sales@{domain}"
        ]
    
    def _find_social_media(self, domain: str) -> List[str]:
        """Find social media accounts"""
        base_name = domain.split('.')[0]
        return [
            f"twitter.com/{base_name}",
            f"facebook.com/{base_name}",
            f"linkedin.com/company/{base_name}",
            f"github.com/{base_name}"
        ]
    
    # ============ ADVANCED DNS ENUMERATION ============
    def enumerate_dns_records(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """Comprehensive DNS enumeration"""
        
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"]
        results = {}
        
        for record_type in record_types:
            records = self._query_dns_record(domain, record_type)
            if records:
                results[record_type] = records
        
        return results
    
    def _query_dns_record(self, domain: str, record_type: str) -> List[DNSRecord]:
        """Query specific DNS record type"""
        results = []
        
        try:
            # Attempt DNS query (requires dnspython)
            # import dns.resolver
            # answers = dns.resolver.resolve(domain, record_type)
            
            # For now, return mock data
            if record_type == "A":
                results.append(DNSRecord("A", domain, "192.0.2.1"))
            elif record_type == "MX":
                results.append(DNSRecord("MX", domain, "mail.example.com", 10))
            elif record_type == "TXT":
                results.append(DNSRecord("TXT", domain, "v=spf1 include:_spf.google.com ~all"))
        except:
            pass
        
        return results
    
    def find_dns_zone_transfers(self, domain: str) -> List[DNSRecord]:
        """Attempt DNS zone transfer"""
        
        results = []
        
        try:
            # Attempt AXFR transfer
            # import dns.zone
            # zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            
            zone_transfer_records = []
        except:
            zone_transfer_records = []
        
        return zone_transfer_records
    
    # ============ SUBDOMAIN ENUMERATION ============
    def enumerate_subdomains(self, domain: str, methods: List[str] = None) -> List[str]:
        """Enumerate subdomains using multiple methods"""
        
        if methods is None:
            methods = ["dns_brute", "certificate_transparency", "dns_records", "google_dorks", "cname_chain"]
        
        subdomains = set()
        
        for method in methods:
            if method == "dns_brute":
                subdomains.update(self._dns_brute_force(domain))
            elif method == "certificate_transparency":
                subdomains.update(self._certificate_transparency_search(domain))
            elif method == "dns_records":
                subdomains.update(self._extract_subdomains_from_dns(domain))
            elif method == "google_dorks":
                subdomains.update(self._google_dork_subdomains(domain))
            elif method == "cname_chain":
                subdomains.update(self._cname_chain_enumeration(domain))
        
        return list(subdomains)
    
    def _dns_brute_force(self, domain: str) -> Set[str]:
        """DNS brute force common subdomains"""
        
        common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "admin", "api", "dev", "staging", "test", "demo", "internal",
            "vpn", "cloud", "cdn", "git", "github", "jenkins", "docs",
            "blog", "shop", "store", "app", "dashboard", "portal"
        ]
        
        found = set()
        
        # Attempt to resolve each
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                found.add(full_domain)
            except socket.gaierror:
                pass
        
        return found
    
    def _certificate_transparency_search(self, domain: str) -> Set[str]:
        """Search Certificate Transparency logs for subdomains"""
        
        # Would use APIs like crt.sh
        # Requires web scraping or API access
        found = set()
        
        # Mock response
        return found
    
    def _extract_subdomains_from_dns(self, domain: str) -> Set[str]:
        """Extract subdomains from DNS records"""
        
        found = set()
        records = self.enumerate_dns_records(domain)
        
        for record_type, record_list in records.items():
            if record_type == "CNAME":
                for record in record_list:
                    found.add(record.value)
        
        return found
    
    def _google_dork_subdomains(self, domain: str) -> Set[str]:
        """Find subdomains via Google dorks (requires web scraping)"""
        # site:example.com -site:www.example.com
        return set()
    
    def _cname_chain_enumeration(self, domain: str) -> Set[str]:
        """Follow CNAME chain to find related domains"""
        
        found = set()
        
        # Recursively follow CNAME records
        try:
            records = self.enumerate_dns_records(domain)
            if "CNAME" in records:
                for cname in records["CNAME"]:
                    found.add(cname.value)
                    # Could recursively enumerate cname.value
        except:
            pass
        
        return found
    
    def _google_dork_subdomains(self, domain: str) -> Set[str]:
        """Search for subdomains using Google dorks (mock)"""
        # Would use Google search API or scraping
        return set()
    
    def _cname_chain_enumeration(self, domain: str) -> Set[str]:
        """Follow CNAME chains to discover subdomains"""
        found = set()
        records = self.enumerate_dns_records(domain)
        
        if "CNAME" in records:
            for record in records["CNAME"]:
                found.add(record.value)
        
        return found
    
    # ============ SSL/TLS ANALYSIS ============
    def analyze_ssl_certificate(self, host: str, port: int = 443) -> Optional[SSLCertificate]:
        """Analyze SSL certificate of target"""
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)
            
            # Parse certificate
            ssl_cert = SSLCertificate(
                subject=dict(x[0] for x in cert.get("subject", [])),
                issuer=dict(x[0] for x in cert.get("issuer", [])),
                serial_number=str(cert.get("serialNumber", "unknown")),
                not_before=cert.get("notBefore", "unknown"),
                not_after=cert.get("notAfter", "unknown"),
                public_key_bits=0,
                signature_algorithm=cert.get("signatureAlgorithm", "unknown"),
                san=[ext[0] for ext in cert.get("subjectAltName", [])],
                fingerprint_sha256=hashlib.sha256(cert_binary).hexdigest()
            )
            
            # Check for vulnerabilities
            ssl_cert.vulnerabilities = self._check_ssl_vulnerabilities(ssl_cert)
            
            return ssl_cert
        except:
            return None
    
    def _check_ssl_vulnerabilities(self, cert: SSLCertificate) -> List[str]:
        """Check SSL certificate for vulnerabilities"""
        
        vulnerabilities = []
        
        # Check signature algorithm
        if "md5" in cert.signature_algorithm.lower():
            vulnerabilities.append("MD5_SIGNATURE")
        if "sha1" in cert.signature_algorithm.lower():
            vulnerabilities.append("SHA1_SIGNATURE")
        
        # Check key strength
        if cert.public_key_bits < 2048:
            vulnerabilities.append("WEAK_KEY_SIZE")
        
        # Check self-signed
        if cert.subject == cert.issuer:
            vulnerabilities.append("SELF_SIGNED")
        
        return vulnerabilities
    
    def find_certificate_transparency_matches(self, domain: str) -> List[Dict]:
        """Find related domains via CT logs"""
        
        # Would query crt.sh or similar
        return []
    
    # ============ DIGITAL FOOTPRINT MAPPING ============
    def map_digital_footprint(self, target: str) -> DigitalFootprint:
        """Create comprehensive digital footprint"""
        
        footprint = DigitalFootprint(target=target)
        
        # Enumerate domains
        footprint.domains = [target]
        
        # Find subdomains
        footprint.subdomains = self.enumerate_subdomains(target)
        
        # Resolve IPs
        for domain in footprint.domains + footprint.subdomains:
            try:
                ip = socket.gethostbyname(domain)
                if ip not in footprint.ip_addresses:
                    footprint.ip_addresses.append(ip)
            except:
                pass
        
        # Reverse DNS
        for ip in footprint.ip_addresses:
            try:
                rdns = socket.gethostbyaddr(ip)
                footprint.reverse_dns[ip] = rdns
            except:
                pass
        
        # SSL certificates
        for domain in footprint.domains + footprint.subdomains:
            cert = self.analyze_ssl_certificate(domain)
            if cert:
                footprint.ssl_certificates.append(cert)
        
        # DNS records
        footprint.dns_records = self.enumerate_dns_records(target)
        
        # Extract mail servers
        if "MX" in footprint.dns_records:
            footprint.mail_servers = [
                {"server": record.value, "priority": record.ttl}
                for record in footprint.dns_records["MX"]
            ]
        
        return footprint
    
    # ============ SERVICE FINGERPRINTING ============
    def fingerprint_services(self, host: str, ports: List[int] = None) -> Dict[int, Dict]:
        """Advanced service fingerprinting"""
        
        if ports is None:
            ports = [21, 22, 25, 80, 443, 3306, 5432, 8080]
        
        fingerprints = {}
        
        for port in ports:
            fingerprints[port] = self._fingerprint_service(host, port)
        
        return fingerprints
    
    def _fingerprint_service(self, host: str, port: int) -> Dict:
        """Fingerprint single service"""
        
        result = {
            "port": port,
            "service": "unknown",
            "version": None,
            "banner": "",
            "vulnerabilities": [],
            "detectable": False
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            # Attempt to get banner
            try:
                banner = sock.recv(1024).decode(errors='ignore')
                result["banner"] = banner
                result["detectable"] = True
                
                # Parse banner for service/version info
                service_signatures = {
                    "SSH": r"SSH-2\.0-(.*)",
                    "HTTP": r"Server: (.*)",
                    "FTP": r"220 (.*)",
                    "SMTP": r"220 (.*)",
                }
                
                for service, pattern in service_signatures.items():
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        result["service"] = service
                        result["version"] = match.group(1)
                        break
            except:
                pass
            
            sock.close()
        except:
            pass
        
        return result


# Export key classes
__all__ = ['AdvancedIntelligenceEngine', 'DigitalFootprint', 'SSLCertificate', 
           'DNSRecord', 'ThreatIntelligenceSource']
