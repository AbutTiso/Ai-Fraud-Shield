# detector/url_safety.py
import re
import requests
from urllib.parse import urlparse
import json

# Known phishing/suspicious domains (Kenya-focused)
SUSPICIOUS_DOMAINS = {
    'mpesa-update.co.ke',
    'safaricom-update.com',
    'mpesa-verify.com',
    'safaricom-promotion.co.ke',
    'mpesa-login.net',
    'safaricom-winner.com',
    'airtel-kenya-update.com',
    'paypal-verify-kenya.com',
    'kcb-banking-update.com',
    'equity-bank-verify.com',
}

# Known legitimate domains (whitelist)
SAFE_DOMAINS = {
    'safaricom.co.ke',
    'airtel.co.ke',
    'telkom.co.ke',
    'kcbgroup.com',
    'equitybank.co.ke',
    'cooperativebank.co.ke',
    'absabank.co.ke',
    'standardmedia.co.ke',
    'nation.africa',
    'm-pesa.com',
    'google.com',
    'microsoft.com',
    'facebook.com',
    'twitter.com',
    'whatsapp.com',
}

def extract_urls(text):
    """Extract all URLs from text"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def check_url_safety(url):
    """Check if a URL is safe"""
    try:
        parsed = urlparse(url.lower())
        domain = parsed.netloc
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check whitelist
        for safe_domain in SAFE_DOMAINS:
            if domain == safe_domain or domain.endswith('.' + safe_domain):
                return {'safe': True, 'domain': domain, 'reason': 'Legitimate domain'}
        
        # Check blacklist
        for suspicious in SUSPICIOUS_DOMAINS:
            if suspicious in domain:
                return {'safe': False, 'domain': domain, 'reason': f'Known scam domain: {suspicious}'}
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'-\w+\.(com|co\.ke)', 'Suspicious subdomain pattern'),
            (r'\d+\.\w+', 'Domain contains numbers'),
            (r'bit\.ly|tinyurl|shorturl|goo\.gl', 'URL shortener - hides destination'),
        ]
        
        for pattern, reason in suspicious_patterns:
            if re.search(pattern, domain):
                return {'safe': False, 'domain': domain, 'reason': reason}
        
        return {'safe': None, 'domain': domain, 'reason': 'Unknown - proceed with caution'}
        
    except Exception as e:
        return {'safe': None, 'domain': 'Unknown', 'reason': 'Could not parse URL'}

def scan_urls_in_text(text):
    """Scan all URLs in text for safety"""
    urls = extract_urls(text)
    results = []
    
    for url in urls:
        safety = check_url_safety(url)
        results.append({
            'url': url,
            'safety': safety
        })
    
    return results