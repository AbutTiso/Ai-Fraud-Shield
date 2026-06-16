# detector/threat_intel.py
"""
Real-time threat intelligence from multiple external sources
Enhanced with local checks, multiple free APIs, caching, and confidence scoring
"""

import re
import json
import hashlib
import requests
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Dict, Optional, List

from django.conf import settings
from django.core.cache import cache


class ThreatIntelligence:
    """
    Integrates multiple external threat feeds with local analysis.
    Free tier: Google Safe Browsing, VirusTotal, OpenPhish, local patterns.
    Works without any API keys using local checks + OpenPhish.
    """
    
    # ============================================================
    # LOCAL THREAT DATABASE - No API needed
    # ============================================================
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
        '.download', '.live', '.win', '.bid', '.loan', '.review',
        '.stream', '.date', '.space', '.website', '.site', '.online',
        '.tech', '.store', '.work', '.link', '.icu', '.cyou', '.bar',
        '.rest', '.uno', '.host', '.press', '.pub', '.trade', '.webcam',
    ]
    
    PHISHING_KEYWORDS = [
        'secure', 'verify', 'login', 'signin', 'update', 'confirm',
        'validate', 'authenticate', 'account', 'payment', 'transaction',
        'alert', 'security', 'warning', 'urgent', 'important',
        'paypal', 'banking', 'webscr', 'cmd', 'dispatch',
    ]
    
    BRAND_IMPERSONATION = {
        'safaricom': ['safaricom.co.ke', 'safaricom.com'],
        'mpesa': ['safaricom.co.ke'],
        'airtel': ['airtel.co.ke', 'airtel.com'],
        'telkom': ['telkom.co.ke'],
        'kcb': ['kcbgroup.com', 'kcb.co.ke'],
        'equity': ['equitybank.co.ke', 'equitybank.com'],
        'coop': ['coopbank.co.ke', 'co-operativebank.co.ke'],
        'absa': ['absabank.co.ke', 'absa.co.ke'],
        'ncba': ['ncbagroup.com', 'ncba.co.ke'],
        'kra': ['kra.go.ke'],
        'ecitizen': ['ecitizen.go.ke'],
        'paypal': ['paypal.com'],
        'google': ['google.com'],
        'microsoft': ['microsoft.com'],
        'facebook': ['facebook.com'],
        'amazon': ['amazon.com'],
        'netflix': ['netflix.com'],
        'dhl': ['dhl.com'],
        'fedex': ['fedex.com'],
    }
    
    SAFE_DOMAINS = {
        'safaricom.com', 'safaricom.co.ke', 'airtel.co.ke', 'telkom.co.ke',
        'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
        'whatsapp.com', 'telegram.org', 'youtube.com', 'wikipedia.org',
        'kcbgroup.com', 'kcb.co.ke', 'equitybank.co.ke', 'coopbank.co.ke',
        'absabank.co.ke', 'kra.go.ke', 'ecitizen.go.ke', 'nssf.go.ke',
        'nhif.go.ke', 'hudumakenya.go.ke', 'ntsa.go.ke',
        'jumia.co.ke', 'kilimall.co.ke', 'microsoft.com', 'apple.com',
        'amazon.com', 'paypal.com', 'github.com', 'zoom.us',
        '127.0.0.1', 'localhost',
    }
    
    def __init__(self):
        self.apis = {}
        
        # Always available - no API key needed
        self.apis['openphish'] = OpenPhishAPI()
        self.apis['local'] = LocalThreatDB(
            self.SUSPICIOUS_TLDS,
            self.PHISHING_KEYWORDS,
            self.BRAND_IMPERSONATION,
            self.SAFE_DOMAINS,
        )
        
        # Optional API-based checks
        if hasattr(settings, 'GOOGLE_SAFE_BROWSING_KEY') and settings.GOOGLE_SAFE_BROWSING_KEY:
            self.apis['google'] = GoogleSafeBrowsingAPI(settings.GOOGLE_SAFE_BROWSING_KEY)
        
        if hasattr(settings, 'VIRUSTOTAL_API_KEY') and settings.VIRUSTOTAL_API_KEY:
            self.apis['virustotal'] = VirusTotalAPI(settings.VIRUSTOTAL_API_KEY)
    
    # ============================================================
    # URL CHECKING
    # ============================================================
    
    def check_url(self, url: str) -> Dict:
        """Check URL against all threat feeds with confidence scoring"""
        cache_key = f"threat_check_{hashlib.md5(url.encode()).hexdigest()}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        results = {}
        malicious_sources = []
        
        # Local check first (fast, no API call)
        local_result = self.local_check_url(url)
        results['local'] = local_result
        
        if local_result.get('is_safe'):
            output = {
                'is_malicious': False,
                'is_safe': True,
                'confidence': 0,
                'risk_score': 0,
                'sources': results,
                'checked_at': datetime.now().isoformat(),
            }
            cache.set(cache_key, output, 7200)
            return output
        
        # External API checks
        for name, api in self.apis.items():
            if name == 'local':
                continue
            try:
                api_result = api.check_url(url)
                results[name] = api_result
                if api_result.get('malicious'):
                    malicious_sources.append({
                        'name': name,
                        'confidence': api_result.get('confidence', 50),
                        'reason': api_result.get('reason', api_result.get('source', name)),
                    })
            except Exception as e:
                results[name] = {'error': str(e), 'malicious': False, 'confidence': 0}
        
        # Calculate overall risk
        is_malicious = len(malicious_sources) > 0
        
        if malicious_sources:
            avg_confidence = sum(s['confidence'] for s in malicious_sources) / len(malicious_sources)
        else:
            avg_confidence = 0
        
        risk_score = min(100, (len(malicious_sources) * 30) + (avg_confidence * 0.4))
        
        output = {
            'is_malicious': is_malicious,
            'is_safe': not is_malicious,
            'confidence': round(avg_confidence, 1),
            'risk_score': round(risk_score, 1),
            'malicious_sources': len(malicious_sources),
            'malicious_source_details': malicious_sources,
            'total_sources_checked': len(self.apis),
            'sources': results,
            'checked_at': datetime.now().isoformat(),
        }
        
        cache.set(cache_key, output, 3600)
        return output
    
    def local_check_url(self, url: str) -> Dict:
        """Fast local check without API calls"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
        except:
            return {'malicious': False, 'confidence': 0}
        
        # Safe domains
        if domain in self.SAFE_DOMAINS or domain.startswith('127.0.0.1') or domain.startswith('localhost'):
            return {'malicious': False, 'is_safe': True, 'confidence': 100}
        
        # Suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return {'malicious': True, 'confidence': 60, 'reason': f'Suspicious TLD: {tld}'}
        
        # Phishing keywords
        keyword_matches = [k for k in self.PHISHING_KEYWORDS if k in domain or k in parsed.path]
        if len(keyword_matches) >= 2:
            return {
                'malicious': True,
                'confidence': min(80, len(keyword_matches) * 20),
                'reason': f'Phishing keywords: {keyword_matches[:3]}',
            }
        
        # Brand impersonation
        for brand, legit_domains in self.BRAND_IMPERSONATION.items():
            if brand in domain and domain not in legit_domains:
                return {
                    'malicious': True,
                    'confidence': 85,
                    'reason': f'Brand impersonation: {brand}',
                }
        
        # IP address as domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            if not domain.startswith('127.') and domain not in ('0.0.0.0', '255.255.255.255'):
                return {'malicious': True, 'confidence': 70, 'reason': 'IP address used as domain'}
        
        # Excessive hyphens or numbers
        if domain.count('-') >= 3:
            return {'malicious': True, 'confidence': 40, 'reason': 'Excessive hyphens'}
        
        if len(re.findall(r'\d', domain)) > 6:
            return {'malicious': True, 'confidence': 35, 'reason': 'Excessive numbers'}
        
        return {'malicious': False, 'confidence': 0}
    
    # ============================================================
    # PHONE CHECKING
    # ============================================================
    
    def check_phone(self, phone_number: str) -> Dict:
        """Check phone against local databases with caching"""
        cleaned = re.sub(r'[^0-9+]', '', phone_number)
        if cleaned.startswith('0'):
            cleaned = '254' + cleaned[1:]
        elif not cleaned.startswith('254') and not cleaned.startswith('+'):
            cleaned = '254' + cleaned[-9:]
        
        cache_key = f"phone_check_{cleaned}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'is_known_scam': False,
            'risk_score': 0,
            'reports_count': 0,
            'sources': {},
        }
        
        # Check PhoneRisk model
        try:
            from .models import PhoneRisk
            phone_risk = PhoneRisk.objects.filter(phone_number=cleaned).first()
            if phone_risk:
                result['sources']['phone_risk'] = {
                    'is_known_scam': phone_risk.risk_score >= 50,
                    'risk_score': phone_risk.risk_score,
                    'reports_count': phone_risk.reports_count,
                }
                result['is_known_scam'] = phone_risk.risk_score >= 50
                result['risk_score'] = phone_risk.risk_score
                result['reports_count'] = phone_risk.reports_count
        except Exception:
            pass
        
        # Check BlockedNumber model
        try:
            from .models import BlockedNumber
            blocked = BlockedNumber.objects.filter(phone_number=cleaned).first()
            if blocked and blocked.status in ('CONFIRMED', 'BLOCKED'):
                result['sources']['blocklist'] = {
                    'is_blocked': True,
                    'confidence': blocked.confidence_score,
                    'status': blocked.status,
                    'report_count': blocked.report_count,
                }
                result['is_known_scam'] = True
                result['risk_score'] = max(result['risk_score'], blocked.confidence_score)
        except Exception:
            pass
        
        cache.set(cache_key, result, 1800)
        return result
    
    # ============================================================
    # EMAIL CHECKING
    # ============================================================
    
    def check_email(self, email: str) -> Dict:
        """Check email against known scam databases"""
        try:
            from .models import EmailRisk
            email_risk = EmailRisk.objects.filter(email_address=email).first()
            if email_risk:
                return {
                    'is_known_scam': email_risk.risk_score >= 50,
                    'risk_score': email_risk.risk_score,
                    'reports_count': email_risk.reports_count,
                }
        except Exception:
            pass
        
        return {'is_known_scam': False, 'risk_score': 0, 'reports_count': 0}
    
    # ============================================================
    # STATISTICS
    # ============================================================
    
    def get_stats(self) -> Dict:
        """Get threat intelligence statistics"""
        return {
            'apis_available': list(self.apis.keys()),
            'total_apis': len(self.apis),
            'always_available': ['openphish', 'local'],
            'requires_api_key': ['google', 'virustotal'],
        }


# ============================================================
# LOCAL THREAT DATABASE
# ============================================================

class LocalThreatDB:
    """Local threat database - No API key needed, always available"""
    
    def __init__(self, suspicious_tlds, phishing_keywords, brand_impersonation, safe_domains):
        self.suspicious_tlds = suspicious_tlds
        self.phishing_keywords = phishing_keywords
        self.brand_impersonation = brand_impersonation
        self.safe_domains = safe_domains
    
    def check_url(self, url):
        """Check URL against local patterns"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
        except:
            return {'malicious': False, 'confidence': 0, 'error': 'Invalid URL'}
        
        # Safe domain check
        if domain in self.safe_domains or domain.startswith('127.0.0.1') or domain.startswith('localhost'):
            return {'malicious': False, 'is_safe': True, 'confidence': 100}
        
        score = 0
        reasons = []
        
        # Check TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                score += 30
                reasons.append(f'Suspicious TLD: {tld}')
                break
        
        # Check keywords
        keyword_count = sum(1 for k in self.phishing_keywords if k in domain or k in parsed.path)
        if keyword_count >= 2:
            score += min(50, keyword_count * 15)
            reasons.append(f'Phishing keywords: {keyword_count}')
        
        # Check brand impersonation
        for brand, legit_domains in self.brand_impersonation.items():
            if brand in domain and domain not in legit_domains:
                score += 40
                reasons.append(f'Impersonating: {brand}')
                break
        
        # IP address check
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            if not domain.startswith('127.'):
                score += 50
                reasons.append('IP address as domain')
        
        return {
            'malicious': score >= 50,
            'confidence': min(100, score),
            'reasons': reasons,
            'score': score,
            'source': 'Local Threat DB',
        }


# ============================================================
# OPENPHISH - Free community feed
# ============================================================

class OpenPhishAPI:
    """OpenPhish - Free community feed, no API key needed"""
    
    FEED_URL = "https://openphish.com/feed.txt"
    
    def __init__(self):
        self.phishing_urls = set()
        self.last_updated = None
        self._update_feed()
    
    def _update_feed(self):
        """Update phishing feed (hourly)"""
        now = datetime.now()
        if self.last_updated and (now - self.last_updated).seconds < 3600:
            return
        
        try:
            response = requests.get(self.FEED_URL, timeout=10)
            if response.status_code == 200:
                self.phishing_urls = set(response.text.strip().split('\n'))
                self.last_updated = now
        except Exception:
            pass
    
    def check_url(self, url):
        self._update_feed()
        
        if url in self.phishing_urls:
            return {
                'malicious': True,
                'confidence': 90,
                'source': 'OpenPhish',
                'reason': 'Found in OpenPhish community feed',
            }
        
        try:
            domain = urlparse(url).netloc.lower()
            for phishing_url in self.phishing_urls:
                if domain in phishing_url:
                    return {
                        'malicious': True,
                        'confidence': 70,
                        'source': 'OpenPhish (domain match)',
                        'reason': 'Domain matches known phishing site',
                    }
        except Exception:
            pass
        
        return {'malicious': False, 'confidence': 0, 'source': 'OpenPhish'}


# ============================================================
# GOOGLE SAFE BROWSING
# ============================================================

class GoogleSafeBrowsingAPI:
    """Google Safe Browsing API - 10,000 free requests per day"""
    
    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    def __init__(self, api_key):
        self.api_key = api_key
    
    def check_url(self, url):
        if not self.api_key:
            return {'malicious': False, 'confidence': 0, 'error': 'No API key configured'}
        
        payload = {
            "client": {"clientId": "AI-Fraud-Shield", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        
        try:
            response = requests.post(
                f"{self.API_URL}?key={self.api_key}",
                json=payload,
                timeout=10,
            )
            
            if response.status_code == 200:
                data = response.json()
                is_malicious = 'matches' in data
                return {
                    'malicious': is_malicious,
                    'confidence': 95 if is_malicious else 10,
                    'details': data.get('matches', []),
                    'source': 'Google Safe Browsing',
                }
            
            return {
                'malicious': False,
                'confidence': 0,
                'error': f'HTTP {response.status_code}',
                'source': 'Google Safe Browsing',
            }
        except Exception as e:
            return {
                'malicious': False,
                'confidence': 0,
                'error': str(e),
                'source': 'Google Safe Browsing',
            }


# ============================================================
# VIRUSTOTAL
# ============================================================

class VirusTotalAPI:
    """VirusTotal API - 500 requests per day on free tier"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def check_url(self, url):
        if not self.api_key:
            return {'malicious': False, 'confidence': 0, 'error': 'No API key configured'}
        
        headers = {"x-apikey": self.api_key}
        url_id = hashlib.sha256(url.encode()).hexdigest()
        
        try:
            # Check existing report first
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=headers,
                timeout=10,
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
                    'source': 'VirusTotal',
                }
            
            # Submit for scanning if not found
            response = requests.post(
                f"{self.base_url}/urls",
                data={"url": url},
                headers=headers,
                timeout=10,
            )
            
            if response.status_code == 200:
                return {
                    'malicious': False,
                    'confidence': 0,
                    'message': 'Submitted for analysis - check back later',
                    'source': 'VirusTotal',
                }
            
            return {
                'malicious': False,
                'confidence': 0,
                'error': 'API limit reached',
                'source': 'VirusTotal',
            }
        except Exception as e:
            return {
                'malicious': False,
                'confidence': 0,
                'error': str(e),
                'source': 'VirusTotal',
            }