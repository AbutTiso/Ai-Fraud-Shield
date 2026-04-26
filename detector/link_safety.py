# detector/link_safety.py
import re
from urllib.parse import urlparse

# Known safe domains (whitelist)
SAFE_DOMAINS = {
    'safaricom.co.ke', 'airtel.co.ke', 'telkom.co.ke',
    'kcbgroup.com', 'equitybank.co.ke', 'cooperativebank.co.ke',
    'absabank.co.ke', 'ncba-group.com', 'standardmedia.co.ke',
    'nation.africa', 'citizen.digital', 'google.com', 'microsoft.com',
    'whatsapp.com', 'facebook.com', 'twitter.com', 'instagram.com'
}

# Known phishing domains (blacklist)
PHISHING_DOMAINS = {
    'mpesa-update.co.ke', 'safaricom-update.com', 'mpesa-verify.com',
    'safaricom-promotion.net', 'mpesa-login.tk', 'safaricom-winner.ml'
}

def analyze_link(url):
    """Analyze a URL for safety"""
    try:
        parsed = urlparse(url.lower())
        domain = parsed.netloc
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check whitelist
        if domain in SAFE_DOMAINS:
            return {
                'safe': True,
                'risk_level': 'LOW',
                'message': 'This domain appears legitimate',
                'color': 'success'
            }
        
        # Check blacklist
        if domain in PHISHING_DOMAINS:
            return {
                'safe': False,
                'risk_level': 'HIGH',
                'message': 'This domain is known for phishing!',
                'color': 'danger'
            }
        
        # Check for suspicious patterns
        suspicious = False
        reasons = []
        
        if re.search(r'-\w+\.(com|co\.ke)', domain):
            suspicious = True
            reasons.append('Suspicious subdomain pattern')
        
        if re.search(r'\d{4,}', domain):
            suspicious = True
            reasons.append('Domain contains numbers')
        
        if 'secure' in domain or 'verify' in domain or 'login' in domain:
            suspicious = True
            reasons.append('Domain uses security-related words')
        
        if suspicious:
            return {
                'safe': False,
                'risk_level': 'MEDIUM',
                'message': f"Suspicious link: {', '.join(reasons)}",
                'color': 'warning'
            }
        
        return {
            'safe': None,
            'risk_level': 'UNKNOWN',
            'message': 'Unknown domain - proceed with caution',
            'color': 'info'
        }
        
    except Exception:
        return {
            'safe': None,
            'risk_level': 'ERROR',
            'message': 'Could not analyze link',
            'color': 'secondary'
        }

def extract_all_links(text):
    """Extract all URLs from text"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # Remove duplicates