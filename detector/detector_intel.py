# detector/threat_intel.py
"""
Real-time threat intelligence from external sources
"""

import requests
import hashlib
from django.conf import settings
from django.core.cache import cache
import json
from typing import Dict, Optional

class ThreatIntelligence:
    """
    Integrates multiple external threat feeds
    Free tier: PhishTank, Google Safe Browsing (limited)
    """
    
    def __init__(self):
        self.apis = {}
        
        # Check for API keys in settings
        if hasattr(settings, 'GOOGLE_SAFE_BROWSING_KEY'):
            self.apis['google'] = GoogleSafeBrowsingAPI(settings.GOOGLE_SAFE_BROWSING_KEY)
        
        if hasattr(settings, 'VIRUSTOTAL_API_KEY'):
            self.apis['virustotal'] = VirusTotalAPI(settings.VIRUSTOTAL_API_KEY)
    
    def check_url(self, url: str) -> Dict:
        """Check URL against all threat feeds"""
        # Check cache first
        cache_key = f"threat_check_{hashlib.md5(url.encode()).hexdigest()}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        results = {}
        
        for name, api in self.apis.items():
            try:
                results[name] = api.check_url(url)
            except Exception as e:
                results[name] = {'error': str(e), 'malicious': False}
        
        # Determine if malicious
        malicious_sources = [r for r in results.values() if r.get('malicious')]
        is_malicious = len(malicious_sources) >= 1
        
        output = {
            'is_malicious': is_malicious,
            'confidence': len(malicious_sources) / max(1, len(self.apis)),
            'sources': results,
            'checked_at': datetime.now().isoformat()
        }
        
        # Cache for 1 hour
        cache.set(cache_key, output, 3600)
        
        return output
    
    def check_phone(self, phone_number: str) -> Dict:
        """Check phone against scam databases"""
        # Free: Use local database first
        from .models import PhoneRisk
        
        try:
            phone_risk = PhoneRisk.objects.get(phone_number=phone_number)
            return {
                'is_known_scam': phone_risk.risk_score >= 50,
                'risk_score': phone_risk.risk_score,
                'reports_count': phone_risk.reports_count,
                'source': 'local_database'
            }
        except PhoneRisk.DoesNotExist:
            return {
                'is_known_scam': False,
                'risk_score': 0,
                'reports_count': 0,
                'source': 'no_data'
            }


class GoogleSafeBrowsingAPI:
    """Google Safe Browsing API - 10,000 free requests per day"""
    
    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    def __init__(self, api_key):
        self.api_key = api_key
    
    def check_url(self, url):
        payload = {
            "client": {
                "clientId": "AI-Fraud-Shield",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(
            f"{self.API_URL}?key={self.api_key}",
            json=payload
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'malicious': 'matches' in data,
                'details': data.get('matches', [])
            }
        else:
            return {'malicious': False, 'error': 'API error'}


class VirusTotalAPI:
    """VirusTotal API - 500 requests per day on free tier"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def check_url(self, url):
        headers = {"x-apikey": self.api_key}
        
        # Submit URL for scanning
        response = requests.post(
            f"{self.base_url}/urls",
            data={"url": url},
            headers=headers
        )
        
        if response.status_code == 200:
            # Get analysis results
            analysis_id = response.json()['data']['id']
            analysis_response = requests.get(
                f"{self.base_url}/analyses/{analysis_id}",
                headers=headers
            )
            
            if analysis_response.status_code == 200:
                stats = analysis_response.json()['data']['attributes']['stats']
                malicious_count = stats.get('malicious', 0)
                
                return {
                    'malicious': malicious_count > 0,
                    'malicious_count': malicious_count,
                    'suspicious_count': stats.get('suspicious', 0),
                    'total_vendors': sum(stats.values())
                }
        
        return {'malicious': False, 'error': 'API limit reached or error'}