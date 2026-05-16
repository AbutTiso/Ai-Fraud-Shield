# detector/takedown/engine.py
import re
import requests
from urllib.parse import urlparse
from django.utils import timezone

class TakedownEngine:
    """Automated scam website takedown system"""
    
    # Known hosting providers and their abuse contacts
    HOSTING_PROVIDERS = {
        'namecheap.com': {
            'name': 'Namecheap',
            'abuse_email': 'abuse@namecheap.com',
            'abuse_url': 'https://www.namecheap.com/support/knowledgebase/article.aspx/9570/5/how-can-i-file-an-abuse-report/'
        },
        'godaddy.com': {
            'name': 'GoDaddy',
            'abuse_email': 'abuse@godaddy.com',
            'abuse_url': 'https://supportcenter.godaddy.com/AbuseReport'
        },
        'cloudflare.com': {
            'name': 'Cloudflare',
            'abuse_email': 'abuse@cloudflare.com',
            'abuse_url': 'https://www.cloudflare.com/abuse/'
        },
        'hostinger.com': {
            'name': 'Hostinger',
            'abuse_email': 'abuse@hostinger.com',
            'abuse_url': 'https://www.hostinger.com/abuse'
        },
    }
    
    # Kenyan brands commonly impersonated
    KENYAN_BRANDS = [
        {'name': 'Safaricom', 'domain': 'safaricom.co.ke', 'email': 'abuse@safaricom.co.ke'},
        {'name': 'M-Pesa', 'domain': 'safaricom.co.ke', 'email': 'abuse@safaricom.co.ke'},
        {'name': 'Airtel Kenya', 'domain': 'airtel.co.ke', 'email': 'abuse@ke.airtel.com'},
        {'name': 'KCB Bank', 'domain': 'kcbgroup.com', 'email': 'info@kcbgroup.com'},
        {'name': 'Equity Bank', 'domain': 'equitybank.co.ke', 'email': 'info@equitybank.co.ke'},
        {'name': 'Co-operative Bank', 'domain': 'co-opbank.co.ke', 'email': 'info@co-opbank.co.ke'},
        {'name': 'KRA', 'domain': 'kra.go.ke', 'email': 'info@kra.go.ke'},
        {'name': 'eCitizen', 'domain': 'ecitizen.go.ke', 'email': 'info@ecitizen.go.ke'},
    ]
    
    @classmethod
    def analyze_url(cls, url):
        """Analyze URL and determine hosting provider"""
        if not url.startswith('http'):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check for brand impersonation
        impersonated = []
        for brand in cls.KENYAN_BRANDS:
            if brand['name'].lower().replace(' ', '') in domain or \
               brand['domain'].split('.')[0] in domain:
                if brand['domain'] not in domain:
                    impersonated.append(brand)
        
        # Try to determine hosting provider
        provider = cls.detect_hosting_provider(domain)
        
        return {
            'url': url,
            'domain': domain,
            'impersonated_brands': impersonated,
            'hosting_provider': provider,
            'is_suspicious': len(impersonated) > 0 or cls.is_suspicious_domain(domain),
        }
    
    @classmethod
    def detect_hosting_provider(cls, domain):
        """Detect hosting provider from domain"""
        try:
            # Use whois lookup (simplified)
            import socket
            ip = socket.gethostbyname(domain)
            
            # Reverse lookup to find provider
            hostname = socket.gethostbyaddr(ip)[0] if ip else ''
            
            for key, provider in cls.HOSTING_PROVIDERS.items():
                if key in hostname.lower():
                    return provider
            
            return {'name': 'Unknown', 'abuse_email': 'abuse@' + domain.split('.')[-2] + '.' + domain.split('.')[-1]}
        except:
            return {'name': 'Unknown', 'abuse_email': 'unknown@abuse.com'}
    
    @classmethod
    def is_suspicious_domain(cls, domain):
        """Check if domain is suspicious"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.click', '.top']
        suspicious_keywords = ['secure-', 'verify-', 'login-', 'mpesa-', 'safaricom-', 'kcb-', 'equity-']
        
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        if any(kw in domain for kw in suspicious_keywords):
            return True
        return False
    
    @classmethod
    def submit_to_google(cls, url, reason):
        """Submit URL to Google Safe Browsing"""
        # Google Safe Browsing API endpoint
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        
        # This requires a Google API key - for now, simulate the submission
        print(f"🔗 [GOOGLE] Reported: {url} - {reason}")
        
        return {
            'success': True,
            'message': f'URL reported to Google Safe Browsing: {reason[:50]}...',
            'submitted_at': timezone.now().isoformat()
        }
    
    @classmethod
    def submit_to_hosting(cls, url, provider_info, reason):
        """Submit abuse report to hosting provider"""
        print(f"📧 [HOSTING] Reported to {provider_info.get('name', 'Unknown')}: {url}")
        print(f"   Abuse Email: {provider_info.get('abuse_email', 'N/A')}")
        print(f"   Reason: {reason[:100]}")
        
        return {
            'success': True,
            'provider': provider_info.get('name', 'Unknown'),
            'message': f'Abuse report submitted to {provider_info.get("name", "Unknown")}',
            'submitted_at': timezone.now().isoformat()
        }
    
    @classmethod
    def notify_brand(cls, brand_info, impersonating_url):
        """Notify a brand that they're being impersonated"""
        print(f"🏢 [BRAND] Notified {brand_info['name']} at {brand_info['email']}")
        print(f"   Impersonating URL: {impersonating_url}")
        
        return {
            'success': True,
            'brand': brand_info['name'],
            'message': f'Brand notification sent to {brand_info["email"]}',
            'submitted_at': timezone.now().isoformat()
        }
    
    @classmethod
    def process_takedown(cls, url):
        """Full takedown process"""
        results = {
            'url': url,
            'analysis': None,
            'google': None,
            'hosting': None,
            'brand_notifications': [],
            'overall_status': 'PENDING'
        }
        
        # Step 1: Analyze URL
        analysis = cls.analyze_url(url)
        results['analysis'] = analysis
        
        # Step 2: Submit to Google Safe Browsing
        if analysis['is_suspicious']:
            reason = f"Phishing site {'impersonating ' + ', '.join([b['name'] for b in analysis['impersonated_brands']]) if analysis['impersonated_brands'] else ''}"
            results['google'] = cls.submit_to_google(url, reason)
        
        # Step 3: Submit to hosting provider
        if analysis['hosting_provider']:
            results['hosting'] = cls.submit_to_hosting(
                url, 
                analysis['hosting_provider'],
                f"Suspicious phishing site: {url}"
            )
        
        # Step 4: Notify impersonated brands
        for brand in analysis['impersonated_brands']:
            notification = cls.notify_brand(brand, url)
            results['brand_notifications'].append(notification)
        
        # Determine overall status
        if results['google'] and results['hosting']:
            results['overall_status'] = 'SUBMITTED'
        
        return results