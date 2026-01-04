#!/usr/bin/env python3
"""
Technology Detection & Fingerprinting Module
Detect web technologies, versions, and map to CVEs
"""

import requests
import re
import json
import urllib3
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse
import hashlib

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class Technology:
    """Detected technology"""
    name: str
    version: str = ""
    category: str = ""  # CMS, Framework, Server, CDN, etc
    confidence: int = 100  # 0-100
    cves: List[str] = field(default_factory=list)
    icon: str = ""
    website: str = ""

@dataclass
class TechStack:
    """Complete technology stack"""
    target: str
    technologies: List[Technology] = field(default_factory=list)
    server: str = ""
    cdn: str = ""
    waf: str = ""
    cms: str = ""
    framework: str = ""
    programming_language: str = ""
    databases: List[str] = field(default_factory=list)
    javascript_libraries: List[str] = field(default_factory=list)

class TechnologyDetector:
    """Detect web technologies like Wappalyzer"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Technology signatures
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict:
        """Load technology detection signatures"""
        return {
            # Web Servers
            "Apache": {
                "headers": {"Server": r"Apache/([\d.]+)"},
                "category": "Web Server",
                "website": "https://httpd.apache.org"
            },
            "Nginx": {
                "headers": {"Server": r"nginx/([\d.]+)"},
                "category": "Web Server",
                "website": "https://nginx.org"
            },
            "Microsoft-IIS": {
                "headers": {"Server": r"Microsoft-IIS/([\d.]+)"},
                "category": "Web Server",
                "website": "https://www.iis.net"
            },
            "LiteSpeed": {
                "headers": {"Server": r"LiteSpeed(?:/(\d+[\d.]*))?"}, 
                "category": "Web Server",
                "website": "https://www.litespeedtech.com"
            },
            
            # CDN & WAF
            "Cloudflare": {
                "headers": {"Server": r"cloudflare", "CF-RAY": r".*"},
                "cookies": ["__cfduid", "__cf_bm"],
                "category": "CDN"
            },
            "Akamai": {
                "headers": {"X-Akamai-Transformed": r".*"},
                "category": "CDN"
            },
            "Sucuri": {
                "headers": {"X-Sucuri-ID": r".*", "X-Sucuri-Cache": r".*"},
                "category": "WAF"
            },
            "ModSecurity": {
                "headers": {"Server": r"Mod_Security"},
                "category": "WAF"
            },
            
            # CMS
            "WordPress": {
                "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
                "headers": {"X-Powered-By": r"WordPress"},
                "meta": {"generator": r"WordPress ([\d.]+)"},
                "category": "CMS",
                "icon": "wordpress.svg"
            },
            "Joomla": {
                "html": [r"/components/com_", r"Joomla!"],
                "meta": {"generator": r"Joomla! ([\d.]+)"},
                "category": "CMS"
            },
            "Drupal": {
                "html": [r"Drupal.settings", r"/sites/default/"],
                "headers": {"X-Generator": r"Drupal ([\d.]+)"},
                "category": "CMS"
            },
            
            # Programming Languages & Frameworks
            "PHP": {
                "headers": {"X-Powered-By": r"PHP/([\d.]+)"},
                "cookies": ["PHPSESSID"],
                "category": "Programming Language"
            },
            "ASP.NET": {
                "headers": {"X-AspNet-Version": r"([\d.]+)", "X-Powered-By": r"ASP.NET"},
                "cookies": ["ASP.NET_SessionId"],
                "category": "Framework"
            },
            "Laravel": {
                "cookies": ["laravel_session"],
                "headers": {"X-Powered-By": r"Laravel"},
                "category": "Framework"
            },
            "Django": {
                "cookies": ["csrftoken", "sessionid"],
                "headers": {"X-Frame-Options": r"DENY"},
                "category": "Framework"
            },
            "Express": {
                "headers": {"X-Powered-By": r"Express"},
                "category": "Framework"
            },
            "Node.js": {
                "headers": {"X-Powered-By": r"Node.js"},
                "category": "Runtime"
            },
            
            # JavaScript Libraries
            "jQuery": {
                "html": [r"jquery[.-]([\d.]+)\.(?:min\.)?js"],
                "category": "JavaScript Library"
            },
            "React": {
                "html": [r"react[.-]([\d.]+)\.(?:min\.)?js", r"__REACT_DEVTOOLS"],
                "category": "JavaScript Framework"
            },
            "Vue.js": {
                "html": [r"vue[.-]([\d.]+)\.(?:min\.)?js"],
                "category": "JavaScript Framework"
            },
            "Angular": {
                "html": [r"ng-version", r"angular[.-]([\d.]+)\.js"],
                "category": "JavaScript Framework"
            },
            
            # Databases (from error messages)
            "MySQL": {
                "html": [r"MySQL.*Error", r"mysqli?_"],
                "category": "Database"
            },
            "PostgreSQL": {
                "html": [r"PostgreSQL.*ERROR", r"pg_query"],
                "category": "Database"
            },
            "MongoDB": {
                "html": [r"MongoError", r"mongodb://"],
                "category": "Database"
            },
            
            # E-commerce
            "Magento": {
                "html": [r"Mage.Cookies", r"/skin/frontend/"],
                "cookies": ["frontend"],
                "category": "E-commerce"
            },
            "WooCommerce": {
                "html": [r"woocommerce", r"wc-"],
                "category": "E-commerce"
            },
            "Shopify": {
                "html": [r"cdn.shopify.com", r"Shopify.theme"],
                "category": "E-commerce"
            }
        }
    
    def detect(self, url: str) -> TechStack:
        """Detect all technologies used by target"""
        from utils.helpers import print_info, print_success
        
        stack = TechStack(target=url)
        
        try:
            print_info(f"[*] Fingerprinting {url}...")
            
            # Get homepage
            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            html = response.text
            headers = response.headers
            cookies = response.cookies
            
            # Detect from headers
            for tech_name, signatures in self.signatures.items():
                confidence = 0
                version = ""
                
                # Check headers
                if "headers" in signatures:
                    for header, pattern in signatures["headers"].items():
                        if header in headers:
                            match = re.search(pattern, headers[header], re.IGNORECASE)
                            if match:
                                confidence = 100
                                if match.groups():
                                    version = match.group(1)
                                break
                
                # Check cookies
                if "cookies" in signatures and confidence < 100:
                    for cookie_name in signatures["cookies"]:
                        if cookie_name in cookies:
                            confidence = 80
                            break
                
                # Check HTML content
                if "html" in signatures and confidence < 100:
                    for pattern in signatures["html"]:
                        match = re.search(pattern, html, re.IGNORECASE)
                        if match:
                            confidence = max(confidence, 70)
                            if match.groups():
                                version = match.group(1)
                
                # Check meta tags
                if "meta" in signatures and confidence < 100:
                    for meta_name, pattern in signatures["meta"].items():
                        meta_match = re.search(
                            f'<meta[^>]+name=["\']?{meta_name}["\']?[^>]+content=["\']?([^"\']+)',
                            html, re.IGNORECASE
                        )
                        if meta_match:
                            version_match = re.search(pattern, meta_match.group(1))
                            if version_match:
                                confidence = 100
                                if version_match.groups():
                                    version = version_match.group(1)
                
                # Add to stack if detected
                if confidence > 0:
                    tech = Technology(
                        name=tech_name,
                        version=version,
                        category=signatures.get("category", "Unknown"),
                        confidence=confidence,
                        icon=signatures.get("icon", ""),
                        website=signatures.get("website", "")
                    )
                    stack.technologies.append(tech)
                    
                    # Categorize
                    if tech.category == "Web Server":
                        stack.server = f"{tech_name} {version}".strip()
                    elif tech.category == "CDN":
                        stack.cdn = tech_name
                    elif tech.category == "WAF":
                        stack.waf = tech_name
                    elif tech.category == "CMS":
                        stack.cms = f"{tech_name} {version}".strip()
                    elif tech.category == "Framework":
                        stack.framework = f"{tech_name} {version}".strip()
                    elif tech.category == "Programming Language":
                        stack.programming_language = f"{tech_name} {version}".strip()
                    elif tech.category == "Database":
                        stack.databases.append(tech_name)
                    elif tech.category in ["JavaScript Library", "JavaScript Framework"]:
                        stack.javascript_libraries.append(f"{tech_name} {version}".strip())
            
            print_success(f"[+] Detected {len(stack.technologies)} technologies")
            
        except Exception as e:
            from utils.helpers import print_warning
            print_warning(f"[!] Detection error: {e}")
        
        return stack
    
    def get_cves_for_technology(self, tech_name: str, version: str) -> List[str]:
        """Get known CVEs for a technology version"""
        # This would integrate with CVE database
        # For now, return common vulnerable versions
        
        vulnerable_versions = {
            "Apache": {
                "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],  # Path Traversal
                "2.4.50": ["CVE-2021-42013"],
                "2.4.29": ["CVE-2017-15710"],
            },
            "PHP": {
                "5.6": ["CVE-2019-11043"],  # RCE in PHP-FPM
                "7.0": ["CVE-2019-11043"],
                "7.1": ["CVE-2019-11043"],
            },
            "WordPress": {
                "5.0": ["CVE-2019-8942", "CVE-2019-8943"],
                "4.9": ["CVE-2018-6389"],
            },
            "Node.js": {
                "8": ["CVE-2018-12116"],
                "10": ["CVE-2019-15606"],
            }
        }
        
        cves = []
        if tech_name in vulnerable_versions:
            for vuln_version, version_cves in vulnerable_versions[tech_name].items():
                if version.startswith(vuln_version):
                    cves.extend(version_cves)
        
        return cves
