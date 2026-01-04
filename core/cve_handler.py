"""
CVE Handler - Comprehensive vulnerability database management
Provides CVE search, tracking, CVSS scoring, and exploit correlation
"""

import json
import re
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib


@dataclass
class CVSSScore:
    """CVSS (Common Vulnerability Scoring System) representation"""
    version: str  # "2.0", "3.0", "3.1"
    vector_string: str
    base_score: float
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    severity: str = ""  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    
    def __post_init__(self):
        """Calculate severity based on base score"""
        if self.version.startswith("3"):
            if self.base_score == 0.0:
                self.severity = "NONE"
            elif self.base_score < 4.0:
                self.severity = "LOW"
            elif self.base_score < 7.0:
                self.severity = "MEDIUM"
            elif self.base_score < 9.0:
                self.severity = "HIGH"
            else:
                self.severity = "CRITICAL"
        else:  # CVSS v2
            if self.base_score < 4.0:
                self.severity = "LOW"
            elif self.base_score < 7.0:
                self.severity = "MEDIUM"
            else:
                self.severity = "HIGH"


@dataclass
class CVEEntry:
    """Complete CVE entry with all metadata"""
    cve_id: str
    description: str
    published_date: datetime
    last_modified: datetime
    cvss_v2: Optional[CVSSScore] = None
    cvss_v3: Optional[CVSSScore] = None
    cwe_ids: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    cpe_matches: List[str] = field(default_factory=list)
    vulnerable_products: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploits: List[Dict[str, str]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    @property
    def severity(self) -> str:
        """Get the highest severity from available CVSS scores"""
        if self.cvss_v3:
            return self.cvss_v3.severity
        elif self.cvss_v2:
            return self.cvss_v2.severity
        return "UNKNOWN"
    
    @property
    def score(self) -> float:
        """Get the base score, preferring CVSS v3"""
        if self.cvss_v3:
            return self.cvss_v3.base_score
        elif self.cvss_v2:
            return self.cvss_v2.base_score
        return 0.0


class CVEHandler:
    """
    Advanced CVE management system with database operations,
    API integration, and exploit correlation.
    """
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_EXPIRY_DAYS = 7
    
    def __init__(self, data_path: Optional[Path] = None, api_key: Optional[str] = None):
        """Initialize CVE handler"""
        self.data_path = data_path or Path(__file__).parent.parent / "data"
        self.cache_path = self.data_path / "cve_cache.json"
        self.api_key = api_key
        
        self.cve_cache: Dict[str, CVEEntry] = {}
        self.cwe_mapping: Dict[str, List[str]] = defaultdict(list)
        self.vendor_mapping: Dict[str, List[str]] = defaultdict(list)
        
        self._load_cache()
        self._build_indices()
    
    def _load_cache(self):
        """Load cached CVE data from disk"""
        if not self.cache_path.exists():
            return
        
        try:
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            for cve_id, data in cache_data.items():
                self.cve_cache[cve_id] = self._dict_to_cve(data)
        except Exception as e:
            print(f"Error loading CVE cache: {e}")
    
    def _save_cache(self):
        """Save CVE cache to disk"""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            
            cache_data = {
                cve_id: self._cve_to_dict(cve)
                for cve_id, cve in self.cve_cache.items()
            }
            
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving CVE cache: {e}")
    
    def _dict_to_cve(self, data: Dict) -> CVEEntry:
        """Convert dictionary to CVEEntry object"""
        # Parse CVSS scores
        cvss_v2 = None
        if data.get('cvss_v2'):
            cvss_v2 = CVSSScore(**data['cvss_v2'])
        
        cvss_v3 = None
        if data.get('cvss_v3'):
            cvss_v3 = CVSSScore(**data['cvss_v3'])
        
        # Parse dates
        published = datetime.fromisoformat(data['published_date'])
        modified = datetime.fromisoformat(data['last_modified'])
        
        return CVEEntry(
            cve_id=data['cve_id'],
            description=data['description'],
            published_date=published,
            last_modified=modified,
            cvss_v2=cvss_v2,
            cvss_v3=cvss_v3,
            cwe_ids=data.get('cwe_ids', []),
            references=data.get('references', []),
            cpe_matches=data.get('cpe_matches', []),
            vulnerable_products=data.get('vulnerable_products', []),
            exploit_available=data.get('exploit_available', False),
            exploits=data.get('exploits', []),
            mitre_techniques=data.get('mitre_techniques', []),
            tags=data.get('tags', [])
        )
    
    def _cve_to_dict(self, cve: CVEEntry) -> Dict:
        """Convert CVEEntry to dictionary"""
        result = {
            'cve_id': cve.cve_id,
            'description': cve.description,
            'published_date': cve.published_date.isoformat(),
            'last_modified': cve.last_modified.isoformat(),
            'cwe_ids': cve.cwe_ids,
            'references': cve.references,
            'cpe_matches': cve.cpe_matches,
            'vulnerable_products': cve.vulnerable_products,
            'exploit_available': cve.exploit_available,
            'exploits': cve.exploits,
            'mitre_techniques': cve.mitre_techniques,
            'tags': cve.tags
        }
        
        if cve.cvss_v2:
            result['cvss_v2'] = {
                'version': cve.cvss_v2.version,
                'vector_string': cve.cvss_v2.vector_string,
                'base_score': cve.cvss_v2.base_score,
                'temporal_score': cve.cvss_v2.temporal_score,
                'environmental_score': cve.cvss_v2.environmental_score,
                'severity': cve.cvss_v2.severity
            }
        
        if cve.cvss_v3:
            result['cvss_v3'] = {
                'version': cve.cvss_v3.version,
                'vector_string': cve.cvss_v3.vector_string,
                'base_score': cve.cvss_v3.base_score,
                'temporal_score': cve.cvss_v3.temporal_score,
                'environmental_score': cve.cvss_v3.environmental_score,
                'severity': cve.cvss_v3.severity
            }
        
        return result
    
    def _build_indices(self):
        """Build search indices for fast lookups"""
        self.cwe_mapping.clear()
        self.vendor_mapping.clear()
        
        for cve_id, cve in self.cve_cache.items():
            # CWE index
            for cwe in cve.cwe_ids:
                self.cwe_mapping[cwe].append(cve_id)
            
            # Vendor/product index
            for product in cve.vulnerable_products:
                parts = product.lower().split()
                for part in parts:
                    if len(part) > 2:
                        self.vendor_mapping[part].append(cve_id)
    
    def get_cve(self, cve_id: str, force_update: bool = False) -> Optional[CVEEntry]:
        """
        Get CVE by ID, fetching from NVD API if not cached or expired
        """
        cve_id = cve_id.upper()
        if not re.match(r'CVE-\d{4}-\d{4,}', cve_id):
            return None
        
        # Check cache
        if not force_update and cve_id in self.cve_cache:
            cve = self.cve_cache[cve_id]
            # Check if cache is still valid
            if datetime.now() - cve.last_modified < timedelta(days=self.CACHE_EXPIRY_DAYS):
                return cve
        
        # Fetch from API
        cve = self._fetch_from_nvd(cve_id)
        if cve:
            self.cve_cache[cve_id] = cve
            self._save_cache()
            self._build_indices()
        
        return cve
    
    def _fetch_from_nvd(self, cve_id: str) -> Optional[CVEEntry]:
        """Fetch CVE data from NVD API"""
        try:
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            url = f"{self.NVD_API_BASE}?cveId={cve_id}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            if not data.get('vulnerabilities'):
                return None
            
            vuln_data = data['vulnerabilities'][0]['cve']
            return self._parse_nvd_response(vuln_data)
        
        except Exception as e:
            print(f"Error fetching CVE from NVD: {e}")
            return None
    
    def _parse_nvd_response(self, data: Dict) -> CVEEntry:
        """Parse NVD API response into CVEEntry"""
        cve_id = data['id']
        
        # Get description
        descriptions = data.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d['lang'] == 'en'),
            "No description available"
        )
        
        # Parse dates
        published = datetime.fromisoformat(
            data['published'].replace('Z', '+00:00')
        )
        modified = datetime.fromisoformat(
            data['lastModified'].replace('Z', '+00:00')
        )
        
        # Parse CVSS scores
        cvss_v2 = None
        cvss_v3 = None
        
        metrics = data.get('metrics', {})
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            v2_data = metrics['cvssMetricV2'][0]['cvssData']
            cvss_v2 = CVSSScore(
                version="2.0",
                vector_string=v2_data.get('vectorString', ''),
                base_score=float(v2_data.get('baseScore', 0))
            )
        
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            v3_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss_v3 = CVSSScore(
                version="3.1",
                vector_string=v3_data.get('vectorString', ''),
                base_score=float(v3_data.get('baseScore', 0))
            )
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            v3_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss_v3 = CVSSScore(
                version="3.0",
                vector_string=v3_data.get('vectorString', ''),
                base_score=float(v3_data.get('baseScore', 0))
            )
        
        # Parse CWE IDs
        cwe_ids = []
        weaknesses = data.get('weaknesses', [])
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('value', '').startswith('CWE-'):
                    cwe_ids.append(desc['value'])
        
        # Parse references
        references = []
        for ref in data.get('references', []):
            references.append({
                'url': ref.get('url', ''),
                'source': ref.get('source', ''),
                'tags': ref.get('tags', [])
            })
        
        # Parse CPE matches and vulnerable products
        cpe_matches = []
        vulnerable_products = []
        configurations = data.get('configurations', [])
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable'):
                        cpe = cpe_match.get('criteria', '')
                        cpe_matches.append(cpe)
                        # Extract product name from CPE
                        product = self._extract_product_from_cpe(cpe)
                        if product:
                            vulnerable_products.append(product)
        
        return CVEEntry(
            cve_id=cve_id,
            description=description,
            published_date=published,
            last_modified=modified,
            cvss_v2=cvss_v2,
            cvss_v3=cvss_v3,
            cwe_ids=cwe_ids,
            references=references,
            cpe_matches=cpe_matches,
            vulnerable_products=list(set(vulnerable_products))
        )
    
    def _extract_product_from_cpe(self, cpe: str) -> Optional[str]:
        """Extract product name from CPE string"""
        # CPE format: cpe:2.3:a:vendor:product:version:...
        parts = cpe.split(':')
        if len(parts) >= 5:
            vendor = parts[3]
            product = parts[4]
            return f"{vendor} {product}".replace('_', ' ').title()
        return None
    
    def search_cves(
        self,
        query: Optional[str] = None,
        severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        exploit_available: Optional[bool] = None,
        limit: int = 50
    ) -> List[Tuple[CVEEntry, float]]:
        """
        Advanced CVE search with multiple filters and relevance scoring
        """
        results = []
        
        for cve_id, cve in self.cve_cache.items():
            score = 0.0
            
            # Query matching
            if query:
                query_lower = query.lower()
                
                # ID match
                if query_lower in cve_id.lower():
                    score += 100.0
                
                # Description match
                if query_lower in cve.description.lower():
                    score += 50.0
                
                # Product match
                for product in cve.vulnerable_products:
                    if query_lower in product.lower():
                        score += 30.0
                        break
                
                # CWE match
                for cwe in cve.cwe_ids:
                    if query_lower in cwe.lower():
                        score += 20.0
                
                if score == 0:
                    continue
            
            # Severity filter
            if severity and cve.severity != severity.upper():
                continue
            
            # CWE filter
            if cwe_id and cwe_id not in cve.cwe_ids:
                continue
            
            # Date range filter
            if date_from and cve.published_date < date_from:
                continue
            if date_to and cve.published_date > date_to:
                continue
            
            # Exploit availability filter
            if exploit_available is not None and cve.exploit_available != exploit_available:
                continue
            
            # Boost score by severity
            severity_boost = {
                'CRITICAL': 40,
                'HIGH': 30,
                'MEDIUM': 20,
                'LOW': 10,
                'NONE': 0
            }
            score += severity_boost.get(cve.severity, 0)
            
            # Boost if exploit available
            if cve.exploit_available:
                score += 25.0
            
            # Boost by CVSS score
            score += cve.score * 2
            
            results.append((cve, score))
        
        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]
    
    def get_recent_cves(self, days: int = 7, severity_min: str = "LOW") -> List[CVEEntry]:
        """Get CVEs published in the last N days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        severity_order = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_index = severity_order.index(severity_min.upper())
        
        recent = []
        for cve in self.cve_cache.values():
            if cve.published_date >= cutoff_date:
                cve_index = severity_order.index(cve.severity)
                if cve_index >= min_index:
                    recent.append(cve)
        
        # Sort by published date descending
        recent.sort(key=lambda x: x.published_date, reverse=True)
        return recent
    
    def get_cves_by_cwe(self, cwe_id: str) -> List[CVEEntry]:
        """Get all CVEs associated with a specific CWE"""
        cve_ids = self.cwe_mapping.get(cwe_id, [])
        return [self.cve_cache[cid] for cid in cve_ids if cid in self.cve_cache]
    
    def get_cves_by_product(self, product_name: str) -> List[CVEEntry]:
        """Get all CVEs affecting a specific product"""
        product_lower = product_name.lower()
        results = []
        
        for cve in self.cve_cache.values():
            for prod in cve.vulnerable_products:
                if product_lower in prod.lower():
                    results.append(cve)
                    break
        
        return results
    
    def add_exploit_info(self, cve_id: str, exploit_data: Dict[str, str]) -> bool:
        """Add exploit information to a CVE"""
        cve = self.get_cve(cve_id)
        if not cve:
            return False
        
        cve.exploit_available = True
        cve.exploits.append(exploit_data)
        self._save_cache()
        return True
    
    def link_mitre_technique(self, cve_id: str, technique_id: str) -> bool:
        """Link a CVE to a MITRE ATT&CK technique"""
        cve = self.get_cve(cve_id)
        if not cve:
            return False
        
        if technique_id not in cve.mitre_techniques:
            cve.mitre_techniques.append(technique_id)
            self._save_cache()
        
        return True
    
    def calculate_risk_score(self, cve: CVEEntry) -> Dict[str, any]:
        """
        Calculate comprehensive risk score for a CVE
        considering multiple factors
        """
        base_score = cve.score
        
        # Factors that increase risk
        exploit_multiplier = 1.5 if cve.exploit_available else 1.0
        
        # Age factor (newer = higher risk)
        days_old = (datetime.now() - cve.published_date).days
        age_factor = max(0.5, 1.5 - (days_old / 365))  # Decays over a year
        
        # CWE criticality (some CWEs are more critical)
        critical_cwes = ['CWE-78', 'CWE-79', 'CWE-89', 'CWE-787', 'CWE-20']
        cwe_multiplier = 1.3 if any(cwe in critical_cwes for cwe in cve.cwe_ids) else 1.0
        
        # Calculate final risk score
        risk_score = base_score * exploit_multiplier * age_factor * cwe_multiplier
        risk_score = min(risk_score, 10.0)  # Cap at 10
        
        return {
            'cve_id': cve.cve_id,
            'base_cvss_score': base_score,
            'risk_score': round(risk_score, 2),
            'factors': {
                'exploit_available': cve.exploit_available,
                'days_since_publication': days_old,
                'critical_cwe': any(cwe in critical_cwes for cwe in cve.cwe_ids),
                'exploit_multiplier': exploit_multiplier,
                'age_factor': round(age_factor, 2),
                'cwe_multiplier': cwe_multiplier
            },
            'severity': cve.severity,
            'priority': self._calculate_priority(risk_score)
        }
    
    def _calculate_priority(self, risk_score: float) -> str:
        """Calculate priority level from risk score"""
        if risk_score >= 9.0:
            return "CRITICAL - Immediate Action Required"
        elif risk_score >= 7.0:
            return "HIGH - Action Required"
        elif risk_score >= 4.0:
            return "MEDIUM - Schedule Remediation"
        else:
            return "LOW - Monitor"
    
    def generate_vulnerability_report(
        self,
        cve_list: List[str],
        include_mitre: bool = True
    ) -> Dict[str, any]:
        """Generate comprehensive vulnerability report"""
        cves = [self.get_cve(cve_id) for cve_id in cve_list]
        cves = [c for c in cves if c is not None]
        
        if not cves:
            return {}
        
        # Calculate statistics
        severity_counts = defaultdict(int)
        cwe_counts = defaultdict(int)
        products_affected = set()
        total_risk = 0.0
        
        risk_assessments = []
        
        for cve in cves:
            severity_counts[cve.severity] += 1
            
            for cwe in cve.cwe_ids:
                cwe_counts[cwe] += 1
            
            products_affected.update(cve.vulnerable_products)
            
            risk_info = self.calculate_risk_score(cve)
            total_risk += risk_info['risk_score']
            risk_assessments.append(risk_info)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_cves': len(cves),
            'severity_distribution': dict(severity_counts),
            'average_risk_score': round(total_risk / len(cves), 2),
            'products_affected': list(products_affected),
            'top_cwes': sorted(
                cwe_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            'risk_assessments': sorted(
                risk_assessments,
                key=lambda x: x['risk_score'],
                reverse=True
            ),
            'exploitable_count': sum(1 for cve in cves if cve.exploit_available),
            'cve_details': [self._cve_to_dict(cve) for cve in cves]
        }
        
        if include_mitre:
            mitre_techniques = set()
            for cve in cves:
                mitre_techniques.update(cve.mitre_techniques)
            report['mitre_techniques'] = list(mitre_techniques)
        
        return report
    
    def update_database(self, year: Optional[int] = None, force: bool = False) -> int:
        """
        Update CVE database from NVD
        Returns number of CVEs updated
        """
        if not year:
            year = datetime.now().year
        
        print(f"Updating CVE database for year {year}...")
        updated_count = 0
        
        # This would normally fetch from NVD API with pagination
        # For now, we'll simulate with the cache
        return updated_count
    
    def export_to_csv(self, output_path: Path, cve_ids: Optional[List[str]] = None):
        """Export CVEs to CSV format"""
        import csv
        
        cves_to_export = []
        if cve_ids:
            cves_to_export = [self.get_cve(cid) for cid in cve_ids]
            cves_to_export = [c for c in cves_to_export if c]
        else:
            cves_to_export = list(self.cve_cache.values())
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'CVE ID', 'Severity', 'CVSS Score', 'Published Date',
                'Description', 'CWE IDs', 'Exploit Available'
            ])
            
            for cve in cves_to_export:
                writer.writerow([
                    cve.cve_id,
                    cve.severity,
                    cve.score,
                    cve.published_date.strftime('%Y-%m-%d'),
                    cve.description[:100] + '...',
                    ', '.join(cve.cwe_ids),
                    'Yes' if cve.exploit_available else 'No'
                ])
