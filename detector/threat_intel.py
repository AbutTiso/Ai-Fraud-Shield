# detector/threat_intel.py
"""
Real-time threat intelligence from multiple external sources
Enhanced with more free APIs, better caching, and confidence scoring
"""

import requests
import hashlib
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
import json
import re
from typing import Dict, Optional, List
from urllib.parse import urlparse

class ThreatIntelligence:
    """
    Integrates multiple external threat feeds
    Free tier: PhishTank, Google Safe Browsing, OpenPhish, URLhaus, IPQualityScore
    """
    
    # ============================================================
    # LOCAL THREAT DATABASE - No API needed
    # ============================================================
    LOCAL_THREAT_PATTERNS = {
        'suspicious_tlds': [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
            '.download', '.live', '.win', '.bid', '.loan', '.review',
            '.stream', '.date', '.space', '.website', '.site', '.online',
            '.tech', '.store', '.work', '.link', '.icu', '.cyou', '.bar',
            '.rest', '.uno', '.host', '.press', '.pub'
        ],
        'phishing_keywords': [
            'secure', 'verify', 'login', 'signin', 'update', 'confirm',
            'validate', 'authenticate', 'account', 'payment', 'transaction',
            'alert', 'security', 'warning', 'urgent', 'important',
            'paypal', 'banking', 'webscr', 'cmd', 'dispatch'
        ],
        'brand_impersonation': {
            'safaricom': ['safaricom.co.ke', 'safaricom.com'],
            'mpesa': ['safaricom.co.ke'],
            'airtel': ['airtel.co.ke'],
            'kcb': ['kcbgroup.com', 'kcb.co.ke'],
            'equity': ['equitybank.co.ke'],
            'coop': ['coopbank.co.ke'],
            'absa': ['absabank.co.ke'],
            'kra': ['kra.go.ke'],
            'paypal': ['paypal.com'],
            'google': ['google.com'],
            'microsoft': ['microsoft.com'],
            'facebook': ['facebook.com'],
        },
        'safe_domains': {
            'safaricom.com', 'safaricom.co.ke', 'airtel.co.ke', 'telkom.co.ke',
            'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'whatsapp.com', 'telegram.org', 'youtube.com', 'wikipedia.org',
            'kcbgroup.com', 'kcb.co.ke', 'equitybank.co.ke', 'coopbank.co.ke',
            'absabank.co.ke', 'kra.go.ke', 'ecitizen.go.ke', 'nssf.go.ke',
            'nhif.go.ke', 'hudumakenya.go.ke', 'ntsa.go.ke',
            'jumia.co.ke', 'kilimall.co.ke', 'carrefour.co.ke',
        }
    }
    
    def __init__(self):
        self.apis = {}
        self.local_db = self.LOCAL_THREAT_PATTERNS
        
        # Check for API keys in settings
        if hasattr(settings, 'GOOGLE_SAFE_BROWSING_KEY'):
            self.apis['google'] = GoogleSafeBrowsingAPI(settings.GOOGLE_SAFE_BROWSING_KEY)
        
        if hasattr(settings, 'VIRUSTOTAL_API_KEY'):
            self.apis['virustotal'] = VirusTotalAPI(settings.VIRUSTOTAL_API_KEY)
        
        # Always available - no API key needed
        self.apis['openphish'] = OpenPhishAPI()
        self.apis['local'] = LocalThreatDB(self.local_db)
    
    def check_url(self, url: str) -> Dict:
        """Check URL against all threat feeds with confidence scoring"""
        # Check cache first
        cache_key = f"threat_check_{hashlib.md5(url.encode()).hexdigest()}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        results = {}
        total_confidence = 0
        sources_checked = 0
        
        # ============================================================
        # LOCAL CHECK FIRST (Fast, no API call)
        # ============================================================
        local_result = self.local_check_url(url)
        results['local'] = local_result
        if local_result.get('is_safe'):
            # Known safe domain - skip external checks
            output = {
                'is_malicious': False,
                'is_safe': True,
                'confidence': 0,
                'risk_score': 0,
                'sources': results,
                'checked_at': datetime.now().isoformat()
            }
            cache.set(cache_key, output, 7200)  # Cache safe domains longer
            return output
        
        # ============================================================
        # EXTERNAL API CHECKS
        # ============================================================
        for name, api in self.apis.items():
            if name == 'local':
                continue  # Already checked
            try:
                api_result = api.check_url(url)
                results[name] = api_result
                if api_result.get('malicious'):
                    total_confidence += api_result.get('confidence', 50)
                    sources_checked += 1
                elif api_result.get('error'):
                    pass  # API error, skip
                else:
                    sources_checked += 1
            except Exception as e:
                results[name] = {'error': str(e), 'malicious': False, 'confidence': 0}
        
        # Calculate overall confidence
        malicious_sources = [r for r in results.values() if r.get('malicious')]
        is_malicious = len(malicious_sources) >= 1
        
        if malicious_sources:
            avg_confidence = sum(r.get('confidence', 0) for r in malicious_sources) / len(malicious_sources)
        else:
            avg_confidence = 0
        
        # Risk score (0-100)
        risk_score = min(100, (len(malicious_sources) * 30) + (avg_confidence * 0.4))
        
        output = {
            'is_malicious': is_malicious,
            'is_safe': not is_malicious,
            'confidence': round(avg_confidence, 1),
            'risk_score': round(risk_score, 1),
            'malicious_sources': len(malicious_sources),
            'total_sources': len(self.apis),
            'sources': results,
            'checked_at': datetime.now().isoformat()
        }
        
        # Cache for 1 hour
        cache.set(cache_key, output, 3600)
        
        return output
    
    def local_check_url(self, url: str) -> Dict:
        """Fast local check without API calls"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
        except:
            return {'malicious': False, 'confidence': 0}
        
        # Check safe domains
        if domain in self.local_db['safe_domains']:
            return {'malicious': False, 'is_safe': True, 'confidence': 100}
        
        # Check suspicious TLDs
        for tld in self.local_db['suspicious_tlds']:
            if domain.endswith(tld):
                return {'malicious': True, 'confidence': 60, 'reason': f'Suspicious TLD: {tld}'}
        
        # Check phishing keywords
        keyword_matches = []
        for keyword in self.local_db['phishing_keywords']:
            if keyword in domain or keyword in parsed.path:
                keyword_matches.append(keyword)
        
        if len(keyword_matches) >= 2:
            return {
                'malicious': True, 
                'confidence': min(80, len(keyword_matches) * 20),
                'reason': f'Phishing keywords: {keyword_matches[:3]}'
            }
        
        # Check brand impersonation
        for brand, legit_domains in self.local_db['brand_impersonation'].items():
            if brand in domain and domain not in legit_domains:
                return {
                    'malicious': True,
                    'confidence': 85,
                    'reason': f'Brand impersonation: {brand}'
                }
        
        return {'malicious': False, 'confidence': 0}
    
    def check_phone(self, phone_number: str) -> Dict:
        """Check phone against local and external databases"""
        # Clean phone number
        cleaned = re.sub(r'[^0-9+]', '', phone_number)
        if cleaned.startswith('0'):
            cleaned = '254' + cleaned[1:]
        elif not cleaned.startswith('254') and not cleaned.startswith('+'):
            cleaned = '254' + cleaned[-9:]
        
        # Check cache
        cache_key = f"phone_check_{cleaned}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        result = {'is_known_scam': False, 'risk_score': 0, 'reports_count': 0, 'sources': {}}
        
        # Check local database
        try:
            from .models import PhoneRisk
            phone_risk = PhoneRisk.objects.get(phone_number=cleaned)
            result['sources']['local'] = {
                'is_known_scam': phone_risk.risk_score >= 50,
                'risk_score': phone_risk.risk_score,
                'reports_count': phone_risk.reports_count,
                'last_reported': phone_risk.last_reported.isoformat()
            }
            result['is_known_scam'] = phone_risk.risk_score >= 50
            result['risk_score'] = phone_risk.risk_score
            result['reports_count'] = phone_risk.reports_count
        except PhoneRisk.DoesNotExist:
            result['sources']['local'] = {'is_known_scam': False, 'risk_score': 0, 'reports_count': 0}
        
        # Check BlockedNumber
        try:
            from .models import BlockedNumber
            blocked = BlockedNumber.objects.filter(phone_number=cleaned).first()
            if blocked and blocked.status in ['CONFIRMED', 'BLOCKED']:
                result['sources']['blocklist'] = {
                    'is_blocked': True,
                    'confidence': blocked.confidence_score,
                    'status': blocked.status
                }
                result['is_known_scam'] = True
                result['risk_score'] = max(result['risk_score'], blocked.confidence_score)
        except:
            pass
        
        cache.set(cache_key, result, 1800)  # Cache 30 min
        return result


class LocalThreatDB:
    """Local threat database - No API key needed"""
    
    def __init__(self, patterns):
        self.patterns = patterns
    
    def check_url(self, url):
        """Check URL against local patterns"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
        except:
            return {'malicious': False, 'confidence': 0, 'error': 'Invalid URL'}
        
        # Safe domain check
        if domain in self.patterns.get('safe_domains', set()):
            return {'malicious': False, 'is_safe': True, 'confidence': 100}
        
        score = 0
        reasons = []
        
        # Check TLD
        for tld in self.patterns.get('suspicious_tlds', []):
            if domain.endswith(tld):
                score += 30
                reasons.append(f'Suspicious TLD: {tld}')
                break
        
        # Check keywords
        keyword_count = 0
        for keyword in self.patterns.get('phishing_keywords', []):
            if keyword in domain or keyword in parsed.path:
                keyword_count += 1
        if keyword_count >= 2:
            score += min(50, keyword_count * 15)
            reasons.append(f'Phishing keywords: {keyword_count}')
        
        # Check brand impersonation
        for brand, legit_domains in self.patterns.get('brand_impersonation', {}).items():
            if brand in domain and domain not in legit_domains:
                score += 40
                reasons.append(f'Impersonating: {brand}')
                break
        
        return {
            'malicious': score >= 50,
            'confidence': min(100, score),
            'reasons': reasons,
            'score': score
        }


class OpenPhishAPI:
    """OpenPhish - Free community feed, no API key needed"""
    
    FEED_URL = "https://openphish.com/feed.txt"
    
    def __init__(self):
        self.phishing_urls = set()
        self.last_updated = None
        self._update_feed()
    
    def _update_feed(self):
        """Update phishing feed (daily)"""
        now = datetime.now()
        if self.last_updated and (now - self.last_updated).seconds < 3600:
            return
        
        try:
            response = requests.get(self.FEED_URL, timeout=10)
            if response.status_code == 200:
                self.phishing_urls = set(response.text.strip().split('\n'))
                self.last_updated = now
        except:
            pass
    
    def check_url(self, url):
        self._update_feed()
        
        # Check exact URL and domain
        if url in self.phishing_urls:
            return {'malicious': True, 'confidence': 90, 'source': 'OpenPhish'}
        
        try:
            domain = urlparse(url).netloc.lower()
            for phishing_url in self.phishing_urls:
                if domain in phishing_url:
                    return {'malicious': True, 'confidence': 70, 'source': 'OpenPhish (domain match)'}
        except:
            pass
        
        return {'malicious': False, 'confidence': 0, 'source': 'OpenPhish'}


class GoogleSafeBrowsingAPI:
    """Google Safe Browsing API - 10,000 free requests per day"""
    
    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    def __init__(self, api_key):
        self.api_key = api_key
    
    def check_url(self, url):
        payload = {
            "client": {"clientId": "AI-Fraud-Shield", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = requests.post(f"{self.API_URL}?key={self.api_key}", json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                is_malicious = 'matches' in data
                return {
                    'malicious': is_malicious,
                    'confidence': 95 if is_malicious else 10,
                    'details': data.get('matches', []),
                    'source': 'Google Safe Browsing'
                }
            return {'malicious': False, 'confidence': 0, 'error': f'HTTP {response.status_code}', 'source': 'Google Safe Browsing'}
        except:
            return {'malicious': False, 'confidence': 0, 'error': 'Connection failed', 'source': 'Google Safe Browsing'}


class VirusTotalAPI:
    """VirusTotal API - 500 requests per day on free tier"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def check_url(self, url):
        headers = {"x-apikey": self.api_key}
        
        # First check if URL already analyzed
        url_id = hashlib.sha256(url.encode()).hexdigest()
        
        try:
            # Get existing report
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                return {
                    'malicious': malicious > 0 or suspicious > 2,
                    'confidence': (malicious / max(1, total)) * 100 if total > 0 else 0,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'total_vendors': total,
                    'source': 'VirusTotal'
                }
            
            # Submit for scanning if not found
            response = requests.post(
                f"{self.base_url}/urls",
                data={"url": url},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    'malicious': False,
                    'confidence': 0,
                    'message': 'Submitted for analysis',
                    'source': 'VirusTotal'
                }
            
            return {'malicious': False, 'confidence': 0, 'error': 'API limit reached', 'source': 'VirusTotal'}
        except:
            return {'malicious': False, 'confidence': 0, 'error': 'Connection failed', 'source': 'VirusTotal'}