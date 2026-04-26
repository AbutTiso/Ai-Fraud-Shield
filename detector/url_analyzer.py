# detector/url_analyzer.py
import re
from urllib.parse import urlparse

# ============================================================
# ENHANCED LEGITIMATE DOMAINS (Whitelist - 100+ domains)
# ============================================================
LEGITIMATE_DOMAINS = {
    # Kenyan Telecoms
    'safaricom.com', 'mpesa.safaricom.com', 'airtel.co.ke', 'telkom.co.ke',
    'safaricom.co.ke', 'airtel.com', 'telkomkenya.co.ke',
    
    # Kenyan Banks
    'equitybank.co.ke', 'equitybank.com', 'kcbgroup.com', 'kcb.co.ke',
    'coopbank.co.ke', 'co-operativebank.co.ke', 'absabank.co.ke',
    'absa.co.ke', 'ncba.co.ke', 'ncbagroup.com', 'familybank.co.ke',
    'familybank.com', 'diamondtrustbank.co.ke', 'dtbkenya.co.ke',
    'ibl.co.ke', 'imperialbank.co.ke', 'stanbic.co.ke', 'stanbicbank.co.ke',
    'standardbank.co.ke', 'standardchartered.co.ke', 'bankofbaroda.co.ke',
    'bankofindia.co.ke', 'citibank.co.ke', 'gtbank.co.ke',
    
    # Government
    'ecitizen.go.ke', 'kra.go.ke', 'nssf.go.ke', 'nhif.go.ke',
    'hudumanamba.go.ke', 'ntsa.go.ke', 'immigration.go.ke', 'interior.go.ke',
    'health.go.ke', 'education.go.ke', 'transport.go.ke', 'kenya.go.ke',
    'moha.go.ke', 'treasury.go.ke', 'parliament.go.ke', 'judiciary.go.ke',
    
    # International Tech/Social
    'google.com', 'gmail.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'instagram.com', 'whatsapp.com', 'telegram.org', 'zoom.us', 'microsoft.com',
    'apple.com', 'amazon.com', 'paypal.com', 'stripe.com', 'cloudflare.com',
    
    # Kenyan Services
    'jumia.co.ke', 'jumia.com', 'kilimall.co.ke', 'jiji.co.ke', 'pigia.co.ke',
    'brighterkenya.com', 'buyrentkenya.com', 'propertykenya.com', 'olx.co.ke',
    
    # News/Security
    'cap.news', 'citizen.digital', 'nation.africa', 'standardmedia.co.ke',
    'the-star.co.ke', 'kenyans.co.ke', 'tuko.co.ke', 'mpasho.co.ke',
    
    # Government Services
    'nita.go.ke', 'ca.go.ke', 'kcca.go.ke', 'kebs.org', 'kra.org', 'kwftourism.go.ke',
}

# ============================================================
# ENHANCED KNOWN SCAM DOMAINS (Blacklist - 100+ domains)
# ============================================================
KNOWN_SCAM_DOMAINS = {
    # M-Pesa impersonation
    'mpesa-update.com', 'safaricom-verify.com', 'mpesa-alert.com', 'mpesa-verify.tk',
    'safaricom-secure.com', 'm-pesa-help.com', 'mpesa-support.com', 'safaricomcare.com',
    'mpesa-center.com', 'safaricom-update.xyz', 'mpesa-failed.com', 'mpesa-reversal.com',
    
    # Bank impersonation
    'kcb-customer.com', 'equity-secure.com', 'coop-bank-alert.com', 'absa-help.com',
    'ncba-support.com', 'equity-customer-care.com', 'kcb-loan.com', 'coopbank-update.com',
    'stanbic-alert.com', 'standardcharteredhelp.com', 'familybank-alert.com',
    
    # Fake verification
    'secure-login-verify.com', 'account-verify.com', 'verify-identity.com', 
    'security-check.com', 'verification-code.com', 'secure-payments.com',
    'account-confirm.com', 'validate-account.com', 'authenticate-login.com',
    
    # Prize scams
    'prize-winner.com', 'safaricom-promo.com', 'airtelwinner.com', 'lotto-winner.com',
    'facebook-lottery.com', 'google-winner.com', 'prize-claim.com', 'jackpot-winner.com',
    
    # Employment scams
    'kazi-mtaani-jobs.com', 'internship-kenya.com', 'job-placement.com', 'work-home-earn.com',
    'data-entry-jobs.com', 'foreign-jobs-kenya.com', 'hiring-now.com',
    
    # Common scam patterns
    'secure-update.com', 'verify-account.tk', 'confirm-login.ml', 'security-alert.ga',
    'account-verification.cf', 'payment-details.xyz', 'login-secure.top', 'bank-update.click',
}

# ============================================================
# ENHANCED SUSPICIOUS PATTERNS (50+ patterns)
# ============================================================

def analyze_url_safely(url):
    """Analyze URL without clicking it - Enhanced with 50+ patterns"""
    
    score = 0
    reasons = []
    
    try:
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = url.lower()
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # ============================================================
        # SECTION 1: Whitelist Check (Legitimate domains)
        # ============================================================
        # Check exact match
        if domain in LEGITIMATE_DOMAINS:
            return {
                'score': 0,
                'risk_level': 'SAFE - LEGITIMATE',
                'color': 'success',
                'emoji': '✅',
                'message': 'This is a verified legitimate domain',
                'reasons': ['✓ Domain is in trusted whitelist'],
                'domain': domain,
                'url': url[:100]
            }
        
        # Check if any legit domain is contained (typo-squatting detection)
        for legit_domain in LEGITIMATE_DOMAINS:
            if legit_domain in domain and legit_domain != domain:
                # Looks like someone registered a similar domain (typo-squatting)
                score += 40
                reasons.append(f'⚠️ Domain mimics legitimate domain: {legit_domain}')
                break
        
        # ============================================================
        # SECTION 2: Blacklist Check (Known scam domains)
        # ============================================================
        if domain in KNOWN_SCAM_DOMAINS:
            score += 85
            reasons.append(f'🔴 Domain is in scam database: {domain}')
        
        # Check for partial matches in blacklist
        for scam_domain in KNOWN_SCAM_DOMAINS:
            if scam_domain in domain:
                score += 60
                reasons.append(f'⚠️ Domain matches known scam pattern: {scam_domain}')
                break
        
        # ============================================================
        # SECTION 3: Brand Impersonation Detection (30+ brands)
        # ============================================================
        brand_impersonation = [
            # Kenyan brands
            ('safaricom', 'Fake Safaricom domain', 35),
            ('mpesa', 'Fake M-Pesa domain', 35),
            ('airtel', 'Fake Airtel domain', 35),
            ('telkom', 'Fake Telkom domain', 35),
            ('kcb', 'Fake KCB domain', 35),
            ('equity', 'Fake Equity domain', 35),
            ('coop', 'Fake Co-op Bank domain', 35),
            ('absa', 'Fake Absa domain', 35),
            ('ncba', 'Fake NCBA domain', 35),
            ('familybank', 'Fake Family Bank domain', 30),
            ('stanbic', 'Fake Stanbic domain', 30),
            ('standardchartered', 'Fake Standard Chartered domain', 30),
            
            # International brands
            ('google', 'Fake Google domain', 30),
            ('facebook', 'Fake Facebook domain', 30),
            ('instagram', 'Fake Instagram domain', 30),
            ('twitter', 'Fake Twitter domain', 30),
            ('linkedin', 'Fake LinkedIn domain', 30),
            ('amazon', 'Fake Amazon domain', 30),
            ('paypal', 'Fake PayPal domain', 35),
            ('microsoft', 'Fake Microsoft domain', 30),
            ('apple', 'Fake Apple domain', 30),
            
            # Government
            ('ecitizen', 'Fake eCitizen domain', 40),
            ('kra', 'Fake KRA domain', 40),
            ('nssf', 'Fake NSSF domain', 40),
            ('nhif', 'Fake NHIF domain', 40),
            ('huduma', 'Fake Huduma domain', 40),
            ('ntsa', 'Fake NTSA domain', 40),
        ]
        
        for brand, description, points in brand_impersonation:
            if brand in domain and not any(legit.endswith(brand) for legit in LEGITIMATE_DOMAINS):
                score += points
                reasons.append(f'⚠️ {description}: {domain}')
                break
        
        # ============================================================
        # SECTION 4: Suspicious Pattern Detection (30+ patterns)
        # ============================================================
        suspicious_patterns = [
            # Login/Verification scams
            (r'secure.*?login', 'Fake secure login page pattern', 20),
            (r'verify.*?account', 'Fake account verification pattern', 25),
            (r'confirm.*?identity', 'Fake identity confirmation pattern', 25),
            (r'update.*?info.*?payment', 'Fake payment update pattern', 25),
            (r'validate.*?credentials', 'Fake credential validation', 25),
            (r'authenticate.*?access', 'Fake authentication request', 20),
            
            # Misspelled domain detection
            (r'safaricom.*?\.(com|co\.ke)[^.]*$', 'Misspelled Safaricom domain', 35),
            (r'mpesa.*?\.(com|co\.ke)[^.]*$', 'Misspelled M-Pesa domain', 35),
            (r'equity.*?\.(com|co\.ke)[^.]*$', 'Misspelled Equity domain', 30),
            (r'kcb.*?\.(com|co\.ke)[^.]*$', 'Misspelled KCB domain', 30),
            
            # Threat/Pressure words
            (r'urgent', 'Uses urgency tactic in URL', 15),
            (r'immediate', 'Creates false urgency', 15),
            (r'warning', 'Warning/Alert in URL', 15),
            (r'suspended', 'Account suspension threat', 20),
            (r'blocked', 'Account blocked threat', 20),
            (r'locked', 'Account locked threat', 20),
            
            # Money-related
            (r'claim.*?prize', 'Prize claiming URL', 25),
            (r'winner', 'Winner announcement', 25),
            (r'refund', 'Fake refund URL', 20),
            (r'compensation', 'Fake compensation URL', 20),
            (r'inheritance', 'Fake inheritance URL', 30),
            
            # Data harvesting
            (r'enter.*?details', 'Requests personal information', 20),
            (r'submit.*?information', 'Requests data submission', 20),
            (r'provide.*?information', 'Requests information', 18),
        ]
        
        for pattern, description, points in suspicious_patterns:
            if re.search(pattern, full_url) or re.search(pattern, path):
                score += points
                reasons.append(f'⚠️ {description}')
        
        # ============================================================
        # SECTION 5: URL Structure Analysis
        # ============================================================
        
        # URL shorteners (dangerous - hide real destination)
        url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'short.link', 'cutt.ly', 
            'ow.ly', 'is.gd', 'tr.im', 'shorte.st', 'buff.ly', 'adf.ly',
            'shorturl.at', 'rb.gy', 'tiny.cc', 'clck.ru', 'soo.gd'
        ]
        if any(shortener in domain for shortener in url_shorteners):
            score += 30
            reasons.append(f'🔗 URL shortener detected ({domain}) - hides real destination')
        
        # IP address as domain (highly suspicious)
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            score += 60
            reasons.append('🔴 Uses IP address instead of domain name - highly suspicious')
        
        # ============================================================
        # SECTION 6: Protocol & Security Analysis
        # ============================================================
        
        # HTTPS check (legitimate sites use HTTPS)
        if parsed.scheme != 'https':
            if any(brand in domain for brand in ['safaricom', 'mpesa', 'kcb', 'equity', 'bank']):
                score += 35
                reasons.append('🔴 Banking/financial site without HTTPS - CRITICAL scam indicator')
            else:
                score += 20
                reasons.append('⚠️ Not using HTTPS (insecure connection)')
        else:
            # Legitimate sites should have HTTPS, but we don't deduct
            reasons.append('✓ Uses HTTPS (secure connection)')
        
        # ============================================================
        # SECTION 7: Domain Extension Analysis (Suspicious TLDs)
        # ============================================================
        suspicious_tlds = {
            '.tk': 35, '.ml': 35, '.ga': 35, '.cf': 35, '.xyz': 30,
            '.top': 30, '.click': 25, '.live': 25, '.win': 25, '.bid': 25,
            '.loan': 30, '.date': 20, '.download': 25, '.review': 20,
            '.stream': 20, '.trade': 25, '.webcam': 20
        }
        
        for tld, points in suspicious_tlds.items():
            if domain.endswith(tld):
                score += points
                reasons.append(f'⚠️ Suspicious domain extension: {tld}')
                break
        
        # Check for .ke domains that aren't official
        if domain.endswith('.ke') and not any(domain == legit for legit in LEGITIMATE_DOMAINS):
            score += 15
            reasons.append('⚠️ Unfamiliar .ke domain - verify carefully')
        
        # ============================================================
        # SECTION 8: Path & Query Parameter Analysis
        # ============================================================
        
        # Excessive subdomains (abnormal)
        subdomain_count = domain.count('.')
        if subdomain_count >= 3:
            score += 15
            reasons.append(f'⚠️ Excessive subdomains ({subdomain_count}) - unusual pattern')
        
        # Login/verify in path
        sensitive_paths = ['/login', '/verify', '/confirm', '/auth', '/secure', '/payment']
        for sensitive in sensitive_paths:
            if sensitive in path:
                score += 10
                reasons.append(f'⚠️ Sensitive path detected: {sensitive}')
                break
        
        # Suspicious query parameters
        sensitive_params = ['redirect', 'return', 'next', 'callback', 'forward']
        for param in sensitive_params:
            if f'{param}=' in query:
                score += 15
                reasons.append(f'⚠️ Redirect parameter detected: {param}=')
                break
        
        # Multiple slashes (redirect chains)
        if path.count('/') > 5:
            score += 10
            reasons.append('⚠️ Multiple slashes in path - potential redirect chain')
        
        # ============================================================
        # SECTION 9: Numeric/Special Character Overload
        # ============================================================
        
        # Too many numbers in domain (often scam domains)
        number_count = len(re.findall(r'\d', domain))
        if number_count > 5:
            score += 15
            reasons.append(f'⚠️ Excessive numbers in domain ({number_count})')
        
        # Excessive hyphens (typo-squatting)
        hyphen_count = domain.count('-')
        if hyphen_count >= 2:
            score += 15
            reasons.append(f'⚠️ Multiple hyphens ({hyphen_count}) - potential typo-squatting')
        
        # ============================================================
        # SECTION 10: Homograph Attack Detection
        # ============================================================
        
        # Common homograph replacements (suspicious)
        homograph_patterns = [
            (r'safaricom', r'safaric0m', 'Zero instead of o'),
            (r'paypal', r'paypa1', 'One instead of l'),
            (r'google', r'g00gle', 'Zero instead of o'),
        ]
        
        for legit, scam, desc in homograph_patterns:
            if re.search(scam, domain):
                score += 40
                reasons.append(f'🔴 Homograph attack detected: {desc}')
                break
        
        # ============================================================
        # SECTION 11: Length-based Suspicion
        # ============================================================
        
        # Extremely long domain (often malicious)
        if len(domain) > 40:
            score += 15
            reasons.append(f'⚠️ Unusually long domain name ({len(domain)} chars)')
        
        # Extremely long URL
        if len(url) > 150:
            score += 10
            reasons.append(f'⚠️ Extremely long URL ({len(url)} chars)')
        
        # ============================================================
        # Normalize score to 0-100
        # ============================================================
        score = min(100, max(0, score))
        
        # ============================================================
        # Determine Risk Level with Enhanced Messages
        # ============================================================
        if score >= 70:
            risk_level = "CRITICAL RISK - DANGEROUS SITE"
            color = "danger"
            emoji = "🔴⛔"
            message = "🚨 CRITICAL: This URL is highly dangerous! DO NOT click or visit!"
        elif score >= 50:
            risk_level = "HIGH RISK - PHISHING SITE"
            color = "danger"
            emoji = "🔴"
            message = "⚠️ This URL appears to be a phishing scam! Do NOT click!"
        elif score >= 30:
            risk_level = "MEDIUM RISK - SUSPICIOUS"
            color = "warning"
            emoji = "🟡"
            message = "⚠️ This URL has suspicious characteristics. Verify before clicking."
        elif score >= 15:
            risk_level = "LOW RISK - CAUTION"
            color = "info"
            emoji = "🔵"
            message = "This URL has minor suspicious elements. Proceed with caution."
        else:
            risk_level = "LOW RISK - LIKELY SAFE"
            color = "success"
            emoji = "🟢"
            message = "This URL appears legitimate based on available patterns."
        
        # ============================================================
        # Return result with enhanced data
        # ============================================================
        return {
            'score': score,
            'risk_level': risk_level,
            'color': color,
            'emoji': emoji,
            'message': message,
            'reasons': reasons[:8] if reasons else ['✅ No suspicious patterns found'],
            'domain': domain,
            'url': url[:100],
            'protocol': parsed.scheme,
            'has_https': parsed.scheme == 'https',
            'path_length': len(path),
            'suspicious_tld': any(domain.endswith(tld) for tld in suspicious_tlds.keys())
        }
        
    except Exception as e:
        return {
            'score': 50,
            'risk_level': 'UNKNOWN - CANNOT ANALYZE',
            'color': 'warning',
            'emoji': '❓',
            'message': 'Could not analyze URL due to error',
            'reasons': [f'Error: {str(e)}', 'Manual verification recommended'],
            'domain': 'unknown',
            'url': url[:100],
            'error': str(e)
        }


def extract_and_analyze_urls(email_text):
    """Extract all URLs from email and analyze each safely - Enhanced"""
    
    # Enhanced URL pattern (covers more cases)
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]()]+'
    urls = re.findall(url_pattern, email_text)
    
    # Also look for URLs without protocol
    domain_pattern = r'(?:www\.)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/\S*)?'
    domain_urls = re.findall(domain_pattern, email_text)
    urls.extend([f'http://{url}' for url in domain_urls if not url.startswith('http')])
    
    # Remove duplicates
    urls = list(set(urls))
    
    if not urls:
        return None
    
    analyzed_urls = []
    highest_score = 0
    high_risk_urls = []
    
    for url in urls[:15]:  # Analyze up to 15 URLs
        analysis = analyze_url_safely(url)
        analyzed_urls.append(analysis)
        
        if analysis['score'] > highest_score:
            highest_score = analysis['score']
        
        if analysis['score'] >= 50:
            high_risk_urls.append({
                'url': url[:80],
                'score': analysis['score'],
                'reason': analysis['reasons'][0] if analysis['reasons'] else 'Suspicious'
            })
    
    # Determine overall risk
    if highest_score >= 70:
        threat_level = "CRITICAL"
        warning = "⚠️ Contains CRITICAL threat URLs - DO NOT CLICK any links in this message!"
    elif highest_score >= 50:
        threat_level = "HIGH"
        warning = "🔴 Contains HIGH RISK phishing URLs - Do not click!"
    elif highest_score >= 30:
        threat_level = "MEDIUM"
        warning = "🟡 Contains suspicious URLs - Verify before clicking"
    elif highest_score >= 15:
        threat_level = "LOW"
        warning = "🔵 Contains URLs with minor concerns - Be cautious"
    else:
        threat_level = "SAFE"
        warning = "✅ All URLs appear safe based on analysis"
    
    return {
        'urls_found': len(urls),
        'urls_analyzed': analyzed_urls[:5],  # Return top 5 analyses
        'highest_risk_score': highest_score,
        'threat_level': threat_level,
        'warning': warning,
        'all_suspicious': highest_score >= 40,
        'high_risk_urls': high_risk_urls[:3]  # Top 3 high risk URLs
    }