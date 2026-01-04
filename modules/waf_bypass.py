#!/usr/bin/env python3
"""
WAF/CDN Detection and Bypass Module
Detect Cloudflare, Akamai, Sucuri and attempt bypass techniques
"""

import requests
import time
import random
import urllib3
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class WAFInfo:
    """WAF/CDN information"""
    name: str = ""
    detected: bool = False
    bypass_possible: bool = False
    real_ip: str = ""
    bypass_methods: List[str] = None
    
    def __post_init__(self):
        if self.bypass_methods is None:
            self.bypass_methods = []

class WAFBypass:
    """WAF detection and bypass techniques"""
    
    def __init__(self):
        self.session = requests.Session()
        
    def detect_waf(self, url: str) -> WAFInfo:
        """Detect WAF/CDN protection"""
        from utils.helpers import print_info, print_success, print_warning
        
        info = WAFInfo()
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Cloudflare detection
            if any(key in headers for key in ['CF-RAY', 'cf-ray', 'CF-Cache-Status']):
                info.name = "Cloudflare"
                info.detected = True
                print_warning("[!] Cloudflare detected")
                
                # Try to find real IP
                real_ip = self._find_real_ip_cloudflare(url)
                if real_ip:
                    info.real_ip = real_ip
                    info.bypass_possible = True
                    info.bypass_methods.append("Direct IP access")
                    print_success(f"[+] Found real IP: {real_ip}")
            
            # Akamai detection
            elif 'X-Akamai-Transformed' in headers or 'Akamai' in headers.get('Server', ''):
                info.name = "Akamai"
                info.detected = True
                print_warning("[!] Akamai CDN detected")
            
            # Sucuri detection
            elif 'X-Sucuri-ID' in headers or 'sucuri' in headers.get('Server', '').lower():
                info.name = "Sucuri"
                info.detected = True
                print_warning("[!] Sucuri WAF detected")
            
            # ModSecurity detection
            elif 'Mod_Security' in headers.get('Server', '') or 'NOYB' in headers:
                info.name = "ModSecurity"
                info.detected = True
                print_warning("[!] ModSecurity detected")
            
            # Generic WAF detection
            elif response.status_code in [403, 406, 429]:
                # Test with malicious payload
                test_response = self.session.get(
                    url + "?test=<script>alert(1)</script>",
                    timeout=10, verify=False
                )
                if test_response.status_code in [403, 406]:
                    info.name = "Generic WAF"
                    info.detected = True
                    print_warning("[!] Generic WAF detected")
            
            if not info.detected:
                print_info("[*] No WAF detected")
                
        except Exception as e:
            print_warning(f"[!] WAF detection error: {e}")
        
        return info
    
    def _find_real_ip_cloudflare(self, url: str) -> Optional[str]:
        """Try to find real IP behind Cloudflare"""
        from urllib.parse import urlparse
        import socket
        
        domain = urlparse(url).netloc
        
        # Method 1: Check common subdomains (often not behind CF)
        subdomains = ['direct', 'origin', 'admin', 'cpanel', 'webmail', 'ftp', 'mail', 'smtp']
        
        for sub in subdomains:
            try:
                test_domain = f"{sub}.{domain}"
                ip = socket.gethostbyname(test_domain)
                
                # Check if it's not Cloudflare IP
                if not self._is_cloudflare_ip(ip):
                    return ip
            except:
                pass
        
        # Method 2: DNS history (would need external API)
        # Method 3: Check for old DNS records
        
        return None
    
    def _is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to Cloudflare"""
        # Cloudflare IP ranges (simplified)
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
    
    def bypass_cloudflare(self, url: str) -> Dict[str, any]:
        """Attempt Cloudflare bypass techniques"""
        from utils.helpers import print_info, print_success, print_warning
        
        results = {
            "bypassed": False,
            "method": None,
            "working_url": None,
            "techniques_tried": []
        }
        
        # Technique 1: User-Agent rotation
        print_info("[*] Trying User-Agent rotation...")
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)',
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
        ]
        
        for ua in user_agents:
            try:
                response = self.session.get(
                    url,
                    headers={'User-Agent': ua},
                    timeout=10, verify=False
                )
                if response.status_code == 200 and 'Cloudflare' not in response.text:
                    results["bypassed"] = True
                    results["method"] = f"User-Agent: {ua[:50]}"
                    results["working_url"] = url
                    print_success(f"[+] Bypass successful with UA rotation!")
                    break
            except:
                pass
        
        results["techniques_tried"].append("User-Agent rotation")
        
        # Technique 2: Origin IP access
        info = self.detect_waf(url)
        if info.real_ip:
            print_info(f"[*] Trying direct IP access: {info.real_ip}")
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                direct_url = f"{parsed.scheme}://{info.real_ip}{parsed.path}"
                
                response = self.session.get(
                    direct_url,
                    headers={'Host': parsed.netloc},
                    timeout=10, verify=False
                )
                if response.status_code == 200:
                    results["bypassed"] = True
                    results["method"] = "Direct IP access"
                    results["working_url"] = direct_url
                    print_success(f"[+] Bypass successful via direct IP!")
            except:
                pass
            
            results["techniques_tried"].append("Direct IP access")
        
        # Technique 3: HTTP/2 fingerprint
        # Technique 4: TLS fingerprint modification
        # (Would require more complex implementation)
        
        return results
    
    def detect_captcha(self, html: str) -> Dict[str, any]:
        """Detect CAPTCHA systems"""
        captcha_info = {
            "detected": False,
            "type": None,
            "bypassable": False
        }
        
        # reCAPTCHA detection
        if 'grecaptcha' in html or 'recaptcha' in html.lower():
            captcha_info["detected"] = True
            
            if 'recaptcha/api.js' in html or 'recaptcha/api2' in html:
                captcha_info["type"] = "reCAPTCHA v2"
            elif 'recaptcha/enterprise.js' in html:
                captcha_info["type"] = "reCAPTCHA Enterprise"
            elif 'grecaptcha.execute' in html:
                captcha_info["type"] = "reCAPTCHA v3"
                captcha_info["bypassable"] = True  # v3 is score-based
        
        # hCaptcha detection
        elif 'hcaptcha' in html.lower():
            captcha_info["detected"] = True
            captcha_info["type"] = "hCaptcha"
        
        # Cloudflare Turnstile
        elif 'turnstile' in html.lower() or 'cf-turnstile' in html:
            captcha_info["detected"] = True
            captcha_info["type"] = "Cloudflare Turnstile"
        
        return captcha_info
