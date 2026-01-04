"""
API Client - HTTP client for external API integrations
Handles rate limiting, retries, and authentication
"""

import requests
import time
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
import json


class APIClient:
    """
    Generic API client with rate limiting and retry logic
    """
    
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        rate_limit: int = 10,  # requests per minute
        timeout: int = 30
    ):
        """
        Initialize API client
        
        Args:
            base_url: Base URL for API
            api_key: API key for authentication
            rate_limit: Maximum requests per minute
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.timeout = timeout
        
        self.session = requests.Session()
        self.request_times = []
    
    def _check_rate_limit(self):
        """Check and enforce rate limiting"""
        now = datetime.now()
        # Remove requests older than 1 minute
        self.request_times = [
            t for t in self.request_times
            if now - t < timedelta(minutes=1)
        ]
        
        # If at rate limit, wait
        if len(self.request_times) >= self.rate_limit:
            oldest = min(self.request_times)
            wait_time = 60 - (now - oldest).total_seconds()
            if wait_time > 0:
                time.sleep(wait_time)
                self.request_times = []
        
        self.request_times.append(now)
    
    def _get_headers(self, additional_headers: Optional[Dict] = None) -> Dict:
        """Build request headers"""
        headers = {
            'User-Agent': 'PUPMAS/1.0',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    def get(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        retry: int = 3
    ) -> Optional[Dict]:
        """
        Make GET request
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            headers: Additional headers
            retry: Number of retry attempts
        
        Returns:
            Response data as dict or None on failure
        """
        self._check_rate_limit()
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self._get_headers(headers)
        
        for attempt in range(retry):
            try:
                response = self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:  # Rate limited
                    wait_time = int(response.headers.get('Retry-After', 60))
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"API request failed: {response.status_code}")
                    return None
            
            except requests.exceptions.RequestException as e:
                print(f"Request error: {e}")
                if attempt < retry - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                return None
        
        return None
    
    def post(
        self,
        endpoint: str,
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        retry: int = 3
    ) -> Optional[Dict]:
        """Make POST request"""
        self._check_rate_limit()
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self._get_headers(headers)
        
        for attempt in range(retry):
            try:
                response = self.session.post(
                    url,
                    data=data,
                    json=json_data,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code in [200, 201]:
                    return response.json()
                elif response.status_code == 429:
                    wait_time = int(response.headers.get('Retry-After', 60))
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"API request failed: {response.status_code}")
                    return None
            
            except requests.exceptions.RequestException as e:
                print(f"Request error: {e}")
                if attempt < retry - 1:
                    time.sleep(2 ** attempt)
                    continue
                return None
        
        return None
    
    def close(self):
        """Close session"""
        self.session.close()


class ShodanClient(APIClient):
    """Shodan API client"""
    
    def __init__(self, api_key: str):
        super().__init__(
            base_url="https://api.shodan.io",
            api_key=api_key,
            rate_limit=1  # Shodan has strict rate limits
        )
    
    def search_host(self, ip: str) -> Optional[Dict]:
        """Search for host information"""
        return self.get(f"shodan/host/{ip}", params={'key': self.api_key})
    
    def search(self, query: str, limit: int = 100) -> Optional[Dict]:
        """Search Shodan database"""
        return self.get(
            "shodan/host/search",
            params={'key': self.api_key, 'query': query, 'limit': limit}
        )


class VirusTotalClient(APIClient):
    """VirusTotal API client"""
    
    def __init__(self, api_key: str):
        super().__init__(
            base_url="https://www.virustotal.com/api/v3",
            api_key=api_key,
            rate_limit=4  # 4 requests per minute for free tier
        )
    
    def get_file_report(self, file_hash: str) -> Optional[Dict]:
        """Get file analysis report"""
        return self.get(f"files/{file_hash}")
    
    def get_url_report(self, url: str) -> Optional[Dict]:
        """Get URL analysis report"""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return self.get(f"urls/{url_id}")
    
    def get_domain_report(self, domain: str) -> Optional[Dict]:
        """Get domain report"""
        return self.get(f"domains/{domain}")


class ExploitDBClient:
    """Exploit-DB search client"""
    
    BASE_URL = "https://www.exploit-db.com"
    
    def search(self, query: str) -> list:
        """Search Exploit-DB (requires web scraping or API key)"""
        # This would require either:
        # 1. Official API access
        # 2. Web scraping (not recommended)
        # 3. Using searchsploit command-line tool
        
        # Placeholder for demonstration
        return []


class NVDClient(APIClient):
    """National Vulnerability Database client"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            api_key=api_key,
            rate_limit=5 if api_key else 1  # 5 with key, 1 without
        )
    
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Get CVE details"""
        return self.get("", params={'cveId': cve_id})
    
    def search_cves(
        self,
        keyword: Optional[str] = None,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None
    ) -> Optional[Dict]:
        """Search CVEs"""
        params = {}
        if keyword:
            params['keywordSearch'] = keyword
        if pub_start_date:
            params['pubStartDate'] = pub_start_date
        if pub_end_date:
            params['pubEndDate'] = pub_end_date
        
        return self.get("", params=params)
