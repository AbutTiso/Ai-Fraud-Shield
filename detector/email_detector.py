# detector/email_detector.py
import re
from urllib.parse import urlparse
import html
from datetime import datetime

class EmailScamDetector:
    """Global email scam detection - NO CLICKS, NO NETWORK REQUESTS"""
    
    def __init__(self):
        # Known legitimate domains (global - no network calls)
        self.legitimate_domains = {
            # African Banks & Telcos
            'safaricom.com', 'mpesa.safaricom.com', 'airtel.co.ke', 'airtel.ug', 'airtel.tz',
            'telkom.co.ke', 'mtn.co.za', 'mtn.com.gh', 'mtn.ng', 'vodacom.co.za',
            'equitybank.co.ke', 'kcbgroup.com', 'coopbank.co.ke', 'absabank.co.ke',
            'standardbank.co.za', 'nedbank.co.za', 'fidelitybank.ng', 'gtbank.com',
            'ecobank.com', 'barclays.co.ke', 'stanbicbank.co.ke',
            # US/European Banks
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
            'capitalone.com', 'usbank.com', 'paypal.com', 'stripe.com',
            'hsbc.com', 'lloydsbank.co.uk', 'barclays.co.uk', 'natwest.com',
            'ing.com', 'deutschebank.de', 'bnpparibas.com', 'societegenerale.com',
            # Asian Banks
            'icbc.com.cn', 'bankofchina.com', 'cba.com.au', 'westpac.com.au',
            'dbs.com', 'ocbc.com', 'uob.com.sg', 'maybank.com', 'bca.co.id',
            # E-commerce & Services
            'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp',
            'ebay.com', 'aliexpress.com', 'walmart.com', 'target.com', 'bestbuy.com',
            'flipkart.com', 'shopee.com', 'lazada.com', 'mercari.com',
            # Social Media
            'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'whatsapp.com', 'telegram.org', 'tiktok.com', 'snapchat.com',
            # Tech Companies
            'google.com', 'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
            'dropbox.com', 'github.com', 'slack.com', 'zoom.us', 'discord.com',
            # Government (Global)
            'gov', 'gov.uk', 'gouv.fr', 'bund.de', 'ca.gov', 'usa.gov',
            'service.gov.uk', 'irs.gov', 'hscic.gov.uk', 'nhs.uk',
            # Courier Services
            'dhl.com', 'fedex.com', 'ups.com', 'usps.com', 'dpd.com', 'royalmail.com',
            # Crypto & Fintech
            'coinbase.com', 'binance.com', 'kraken.com', 'crypto.com', 'blockchain.com',
            'revolut.com', 'wise.com', 'venmo.com', 'cash.app', 'payoneer.com',
        }
        
        # URL shorteners (high risk - global)
        self.url_shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 'short.link', 
                                'cutt.ly', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly',
                                'tr.im', 'tiny.cc', 'cli.gs', 'shorturl.at', 'rb.gy',
                                't.co', 'lnkd.in', 'fb.me', 'instagr.am', 'goo.gl',
                                'ow.ly', 's.id', 'shorte.st', 'v.gd', 'x.co', 'qr.net'}
        
        # Suspicious domain extensions (global)
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', 
                                 '.download', '.live', '.win', '.bid', '.loan', '.review', 
                                 '.stream', '.date', '.space', '.website', '.site', '.online',
                                 '.tech', '.store', '.work', '.link', '.gq', '.cf', '.tk', '.ml',
                                 '.fit', '.club', '.xyz', '.icu', '.cyou', '.bond', '.monster'}
        
        # ============ GLOBAL SCAM KEYWORDS BY CATEGORY ============
        
        # Banking & Financial Scams (Global)
        self.banking_scams = [
            (r'bank.*?account.*?(suspended|locked|blocked)', 'Bank Account Suspension Scam', 25),
            (r'verify your (bank|account|identity)', 'Bank Identity Verification Scam', 20),
            (r'unusual activity.*?your account', 'Suspicious Bank Activity Scam', 20),
            (r'secure your account', 'Fake Account Security Scam', 18),
            (r'blocked.*?debit card', 'Debit Card Blocked Scam', 20),
            (r'credit card.*?(suspended|locked)', 'Credit Card Suspension Scam', 20),
            (r'fraud alert.*?(click|verify)', 'Fraud Alert Phishing', 22),
        ]
        
        # Loan & Credit Scams (Global)
        self.loan_scams = [
            (r'loan approval', 'Fake Loan Approval Scam', 18),
            (r'get loan up to', 'Loan Offer Scam', 15),
            (r'low interest loan', 'Low Interest Loan Scam', 15),
            (r'quick loan approval', 'Quick Loan Scam', 15),
            (r'credit score improvement', 'Credit Score Scam', 18),
            (r'bad credit.*?approved', 'Bad Credit Loan Scam', 16),
            (r'consolidate your debt', 'Debt Consolidation Scam', 14),
        ]
        
        # Prize & Lottery Scams (Global)
        self.prize_scams = [
            (r'congratulations.*?(won|winner)', 'Lottery/Congratulations Scam', 20),
            (r'you are the lucky winner', 'Lucky Winner Scam', 20),
            (r'claim your prize', 'Prize Claim Scam', 18),
            (r'lotto.*?(win|won)', 'Lottery Win Scam', 20),
            (r'million.*?dollar.*?prize', 'Million Dollar Prize Scam', 22),
            (r'sweepstakes.*?(winner|won)', 'Sweepstakes Winner Scam', 18),
            (r'cash reward.*?click', 'Cash Reward Scam', 16),
        ]
        
        # IRS/Tax Scams (Global)
        self.tax_scams = [
            (r'(irs|hscic|tax).*?refund', 'Tax Refund Scam', 20),
            (r'tax.*?payment due', 'Fake Tax Payment Scam', 18),
            (r'unpaid taxes', 'Fake Unpaid Tax Scam', 20),
            (r'tax.*?arrears', 'Tax Arrears Scam', 18),
            (r'file your tax return', 'Fake Tax Return Scam', 15),
        ]
        
        # Tech Support Scams (Global)
        self.tech_scams = [
            (r'(microsoft|windows).*?(virus|infected)', 'Fake Microsoft Virus Alert', 22),
            (r'(apple|mac).*?security alert', 'Fake Apple Security Alert', 22),
            (r'suspicious activity.*?(account|device)', 'Suspicious Activity Alert', 18),
            (r'someone logged into your account', 'Unauthorized Login Scam', 18),
            (r'restore your account', 'Fake Account Restore Scam', 16),
            (r'security breach detected', 'Security Breach Scam', 20),
        ]
        
        # Delivery & Courier Scams (Global)
        self.delivery_scams = [
            (r'(dhl|fedex|ups|usps|royalmail).*?(delivery|package)', 'Fake Delivery Scam', 18),
            (r'package.*?delivery failed', 'Delivery Failed Scam', 18),
            (r'unable to deliver your package', 'Failed Delivery Scam', 18),
            (r'tracking number.*?click', 'Fake Tracking Scam', 16),
            (r'parcel.*?waiting for delivery', 'Parcel Delivery Scam', 16),
        ]
        
        # Employment Scams (Global)
        self.employment_scams = [
            (r'work from home', 'Fake Work From Home Scam', 16),
            (r'get paid daily', 'Fake Daily Payment Scam', 15),
            (r'make money online', 'Fake Online Money Scam', 15),
            (r'(recruiting|hiring).*?urgent', 'Urgent Hiring Scam', 14),
            (r'(job offer|job opportunity).*?payment', 'Job Offer Fee Scam', 18),
            (r'(freelance|remote).*?earn', 'Fake Freelance Scam', 14),
        ]
        
        # Romance Scams (Global)
        self.romance_scams = [
            (r'military.*?(need help|financial)', 'Fake Military Romance Scam', 22),
            (r'overseas.*?(money|transfer)', 'Overseas Money Transfer Scam', 20),
            (r'(widow|widower).*?inheritance', 'Fake Inheritance Scam', 20),
            (r'gift.*?send.*?money', 'Gift Card Romance Scam', 18),
        ]
        
        # Investment Scams (Global)
        self.investment_scams = [
            (r'cryptocurrency investment', 'Crypto Investment Scam', 20),
            (r'bitcoin.*?double your money', 'Bitcoin Doubling Scam', 22),
            (r'forex trading.*?guaranteed', 'Fake Forex Trading Scam', 20),
            (r'stock market.*?insider', 'Stock Market Insider Scam', 20),
            (r'get rich quick', 'Get Rich Quick Scam', 18),
            (r'passive income.*?click', 'Fake Passive Income Scam', 16),
            (r'pyramid scheme', 'Pyramid Scheme', 25),
            (r'multi.*?level marketing', 'MLM Recruitment Scam', 18),
        ]
        
        # Subscription Scams (Global)
        self.subscription_scams = [
            (r'(netflix|spotify|hulu|disney\+).*?(payment|billing)', 'Fake Streaming Payment Scam', 20),
            (r'(amazon prime|prime video).*?(subscription|billing)', 'Fake Amazon Prime Scam', 20),
            (r'renew your membership', 'Membership Renewal Scam', 16),
            (r'subscription.*?(expiring|expired)', 'Subscription Expiration Scam', 16),
        ]
        
        # Charity Scams (Global)
        self.charity_scams = [
            (r'donation.*?urgent', 'Urgent Donation Scam', 18),
            (r'help.*?victims of', 'Disaster Relief Scam', 18),
            (r'(charity|nonprofit).*?need your help', 'Charity Donation Scam', 16),
            (r'fundraising campaign', 'Fake Fundraising Scam', 14),
        ]
        
        # Rental & Real Estate Scams (Global)
        self.rental_scams = [
            (r'rental property.*?overseas', 'Overseas Rental Scam', 18),
            (r'send deposit.*?house', 'Fake House Deposit Scam', 20),
            (r'apartment for rent.*?(urgent|cheap)', 'Fake Rental Listing Scam', 16),
        ]
        
        # Nigerian Prince/419 Scams (Global)
        self.nigerian_scams = [
            (r'(prince|princess|royal).*?family', 'Royalty Inheritance Scam', 25),
            (r'inheritance.*?claim your', 'Fake Inheritance Scam', 25),
            (r'(western union|money gram).*?transfer', 'Money Transfer Scam', 22),
            (r'overpayment.*?refund', 'Overpayment Refund Scam', 20),
        ]
        
        # Invoice & Billing Scams (Global)
        self.invoice_scams = [
            (r'invoice.*?attached', 'Fake Invoice Attachment Scam', 18),
            (r'balance due', 'Fake Balance Due Scam', 16),
            (r'overdue payment', 'Overdue Payment Scam', 18),
            (r'final notice.*?bill', 'Final Bill Notice Scam', 16),
        ]
        
        # Region-Specific Scams
        self.region_scams = {
            'africa': [
                (r'mpesa.*?(suspended|blocked)', 'M-Pesa Suspension Scam', 25),
                (r'airtel.*?promotion', 'Airtel Promotion Scam', 15),
                (r'mtn.*?reward', 'MTN Reward Scam', 15),
                (r'(vodacom|orange).*?win', 'Mobile Network Prize Scam', 15),
            ],
            'asia': [
                (r'alipay.*?(suspended|blocked)', 'Alipay Suspension Scam', 20),
                (r'wechat.*?verify', 'WeChat Verification Scam', 18),
                (r'paytm.*?reward', 'Paytm Reward Scam', 15),
                (r'rakuten.*?points', 'Rakuten Points Scam', 14),
            ],
            'europe': [
                (r'vat.*?refund', 'VAT Refund Scam', 16),
                (r'euro.*?lottery', 'Euro Lottery Scam', 18),
                (r'eu.*?tax.*?refund', 'EU Tax Refund Scam', 16),
            ],
            'americas': [
                (r'social security.*?(suspended|blocked)', 'Social Security Suspension Scam', 25),
                (r'medicare.*?fraud alert', 'Medicare Fraud Alert', 20),
                (r'student loan.*?forgiveness', 'Student Loan Forgiveness Scam', 20),
                (r'canada revenue agency', 'CRA Tax Scam', 20),
                (r'afip.*?tax', 'AFIP Tax Scam', 18),
            ],
            'australia': [
                (r'mygov.*?alert', 'MyGov Alert Scam', 20),
                (r'ato.*?tax', 'ATO Tax Scam', 20),
                (r'centrelink.*?payment', 'Centrelink Payment Scam', 18),
            ],
            'middle_east': [
                (r'careem.*?promotion', 'Careem Promotion Scam', 15),
                (r'noon.*?reward', 'Noon Reward Scam', 15),
            ],
        }
    
    # ============ URL EXTRACTION & ANALYSIS METHODS ============
    
    def extract_links_safely(self, text):
        """Extract links from email text WITHOUT visiting them"""
        text = html.unescape(text)
        
        # Find all URLs
        url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Also find obfuscated URLs
        obfuscated_pattern = r'hxxps?://[^\s<>"\'{}|\\^`\[\]]+'
        obfuscated_urls = re.findall(obfuscated_pattern, text, re.IGNORECASE)
        urls.extend([u.replace('hxxp', 'http') for u in obfuscated_urls])
        
        # Remove duplicates while preserving order
        unique_urls = []
        for url in urls:
            if url not in unique_urls:
                unique_urls.append(url)
        
        return unique_urls
    
    def analyze_url_safely(self, url):
        """Analyze URL structure WITHOUT visiting it - PURE TEXT ANALYSIS"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            score = 0
            reasons = []
            
            # Check 1: Is it a known legitimate domain?
            if domain in self.legitimate_domains:
                return {
                    'url': url[:80] + ('...' if len(url) > 80 else ''),
                    'domain': domain,
                    'score': 0,
                    'risk': 'SAFE',
                    'emoji': '✅',
                    'message': 'Known legitimate domain',
                    'reasons': ['Domain is verified and trusted'],
                    'should_block': False
                }
            
            # Check 2: URL shorteners (hides real destination)
            if domain in self.url_shorteners:
                score += 30
                reasons.append(f"⚠️ URL shortener detected ({domain}) - hides real destination")
            
            # Check 3: Suspicious domain extension
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    score += 25
                    reasons.append(f"⚠️ Suspicious domain extension ({tld}) - commonly used by scammers")
                    break
            
            # Check 4: International brand impersonation
            brand_patterns = [
                (r'microsoft.*?\.(com)[^.]*$', 'Fake Microsoft domain', 35),
                (r'apple.*?\.(com)[^.]*$', 'Fake Apple domain', 35),
                (r'google.*?\.(com)[^.]*$', 'Fake Google domain', 35),
                (r'amazon.*?\.(com)[^.]*$', 'Fake Amazon domain', 35),
                (r'paypal.*?\.(com)[^.]*$', 'Fake PayPal domain', 35),
                (r'netflix.*?\.(com)[^.]*$', 'Fake Netflix domain', 30),
                (r'chase.*?\.(com)[^.]*$', 'Fake Chase domain', 35),
                (r'bankofamerica.*?\.(com)[^.]*$', 'Fake Bank of America domain', 35),
                (r'wellsfargo.*?\.(com)[^.]*$', 'Fake Wells Fargo domain', 35),
                (r'hsbc.*?\.(com)[^.]*$', 'Fake HSBC domain', 35),
                (r'safaricom.*?\.(com|co\.ke)[^.]*$', 'Fake Safaricom domain', 35),
                (r'mpesa.*?\.(com|co\.ke)[^.]*$', 'Fake M-Pesa domain', 35),
                (r'dhl.*?\.(com)[^.]*$', 'Fake DHL domain', 30),
                (r'fedex.*?\.(com)[^.]*$', 'Fake FedEx domain', 30),
                (r'ups.*?\.(com)[^.]*$', 'Fake UPS domain', 30),
            ]
            
            for pattern, message, points in brand_patterns:
                if re.search(pattern, domain):
                    score += points
                    reasons.append(f"🔴 {message}: '{domain}'")
                    break
            
            # Check 5: Phishing keywords in domain
            phishing_keywords = [
                'secure', 'verify', 'login', 'update', 'confirm', 'signin', 
                'account', 'alert', 'security', 'validate', 'authentication'
            ]
            for keyword in phishing_keywords:
                if keyword in domain:
                    score += 15
                    reasons.append(f"⚠️ Contains '{keyword}' - common in phishing URLs")
                    break
            
            # Check 6: IP address as domain
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                score += 50
                reasons.append("🔴 Uses IP address instead of domain name - very suspicious!")
            
            # Check 7: Protocol
            if parsed.scheme != 'https':
                score += 15
                reasons.append("⚠️ Not using HTTPS (insecure connection)")
            
            # Check 8: Unusually long URL
            if len(url) > 100:
                score += 10
                reasons.append("⚠️ Unusually long URL (hiding tactic)")
            
            # Check 9: Multiple redirects
            if '//' in url and url.count('//') > 1:
                score += 10
                reasons.append("⚠️ Multiple slashes - possible redirect chain")
            
            # Check 10: Redirect parameters
            if parsed.query and ('redirect' in parsed.query.lower() or 'url=' in parsed.query.lower()):
                score += 15
                reasons.append("⚠️ Contains redirect parameter")
            
            score = min(100, score)
            
            if score >= 60:
                return {
                    'url': url[:80] + ('...' if len(url) > 80 else ''),
                    'domain': domain,
                    'score': score,
                    'risk': 'DANGEROUS',
                    'emoji': '🔴',
                    'message': '⚠️ DANGEROUS LINK - DO NOT CLICK!',
                    'reasons': reasons,
                    'should_block': True
                }
            elif score >= 30:
                return {
                    'url': url[:80] + ('...' if len(url) > 80 else ''),
                    'domain': domain,
                    'score': score,
                    'risk': 'SUSPICIOUS',
                    'emoji': '🟡',
                    'message': '⚠️ Suspicious link - be very careful',
                    'reasons': reasons,
                    'should_block': True
                }
            else:
                return {
                    'url': url[:80] + ('...' if len(url) > 80 else ''),
                    'domain': domain,
                    'score': score,
                    'risk': 'LOW RISK',
                    'emoji': '🟢',
                    'message': 'Link appears safe',
                    'reasons': reasons if reasons else ['No suspicious patterns found'],
                    'should_block': False
                }
                
        except Exception as e:
            return {
                'url': url[:80] + ('...' if len(url) > 80 else ''),
                'domain': 'unknown',
                'score': 50,
                'risk': 'UNKNOWN',
                'emoji': '❓',
                'message': 'Could not analyze link',
                'reasons': [f'Analysis error: {str(e)}'],
                'should_block': True
            }
    
    # ============ EMAIL HEADER ANALYSIS (SPOOF DETECTION) ============
    
    def extract_email_headers(self, email_text):
        """Extract and parse email headers for spoofing detection"""
        
        headers = {}
        lines = email_text.split('\n')
        
        for line in lines[:50]:  # Headers are usually in first 50 lines
            line_lower = line.lower()
            
            if line_lower.startswith('from:'):
                headers['from'] = line[5:].strip()
            elif line_lower.startswith('reply-to:'):
                headers['reply_to'] = line[9:].strip()
            elif line_lower.startswith('return-path:'):
                headers['return_path'] = line[11:].strip()
            elif line_lower.startswith('sender:'):
                headers['sender'] = line[7:].strip()
            elif line_lower.startswith('to:'):
                headers['to'] = line[3:].strip()
            elif line_lower.startswith('subject:'):
                headers['subject'] = line[8:].strip()
        
        return headers

    def analyze_email_headers(self, email_text):
        """Analyze email headers for spoofing attempts - NO NETWORK REQUESTS"""
        
        headers = self.extract_email_headers(email_text)
        warnings = []
        score = 0
        display_name = None
        actual_email = None
        actual_domain = None
        reply_to_domain = None
        
        company_names = ['Safaricom', 'M-Pesa', 'Airtel', 'Telkom', 'Equity', 'KCB', 
                         'PayPal', 'Amazon', 'Apple', 'Microsoft', 'Google', 'Netflix',
                         'DHL', 'FedEx', 'UPS', 'Bank of America', 'Chase', 'Wells Fargo']
        
        # ============ Check 1: Extract display name and actual email ============
        from_header = headers.get('from', '')
        
        # Pattern to extract display name and email: "Name" <email@domain.com>
        name_email_match = re.search(r'"([^"]+)"\s*<([^>]+)>', from_header)
        if not name_email_match:
            # Try without quotes: Name <email@domain.com>
            name_email_match = re.search(r'([^<]+)\s*<([^>]+)>', from_header)
        
        if name_email_match:
            display_name = name_email_match.group(1).strip()
            actual_email = name_email_match.group(2).strip()
            actual_domain = actual_email.split('@')[-1].lower() if '@' in actual_email else ''
            
            # Check 1: Legitimate company names with suspicious email domains
            for company in company_names:
                if company.lower() in display_name.lower():
                    # Display name claims to be a company
                    if actual_domain and actual_domain not in self.legitimate_domains:
                        # But email domain is not legitimate
                        score += 35
                        warnings.append(f"🔴 SPOOFING DETECTED: Display name '{company}' but email is from '{actual_domain}'")
                        warnings.append(f"   Legitimate {company} emails come from @{company.lower()}.com, not @{actual_domain}")
                    break
            
            # Check 2: Display name different from email domain
            if display_name and actual_domain:
                name_words = display_name.lower().split()
                for word in name_words:
                    if word in ['safaricom', 'mpesa', 'airtel', 'paypal', 'amazon', 'apple', 'microsoft']:
                        if word not in actual_domain:
                            score += 25
                            warnings.append(f"⚠️ Suspicious: Display name says '{word}' but email domain is '{actual_domain}'")
                            break
        
        # ============ Check 2: Reply-To vs From mismatch ============
        reply_to = headers.get('reply_to', '')
        if reply_to and actual_email:
            reply_to_domain = reply_to.split('@')[-1].lower() if '@' in reply_to else ''
            if reply_to_domain != actual_domain:
                score += 20
                warnings.append(f"⚠️ Reply-To domain '{reply_to_domain}' doesn't match From domain '{actual_domain}'")
                warnings.append("   Scammers use this to intercept your replies")
        
        # ============ Check 3: Suspicious sender domains ============
        if actual_domain:
            # Check for free email providers impersonating companies
            free_email_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                                     'aol.com', 'protonmail.com', 'mail.com', 'yandex.com']
            
            if actual_domain in free_email_providers:
                # See if display name claims to be a company
                if display_name and any(company.lower() in display_name.lower() for company in company_names):
                    score += 30
                    warnings.append(f"🔴 Company impersonation using free email: @{actual_domain}")
                    warnings.append(f"   Legitimate companies use their own domains, not @{actual_domain}")
            
            # Check for typosquatting
            legitimate_patterns = {
                'safaricom': [r'safaricom', r'safaric0m', r'safaricom-', r'safaricom\.'],
                'paypal': [r'paypal', r'paypall', r'pay-pal'],
                'amazon': [r'amazon', r'amaz0n', r'amzon'],
                'microsoft': [r'microsoft', r'micros0ft', r'micro-soft'],
            }
            
            for legit_name, patterns in legitimate_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, actual_domain):
                        if legit_name not in actual_domain:
                            score += 25
                            warnings.append(f"⚠️ Suspicious domain: '{actual_domain}' looks like '{legit_name}' but isn't")
                            break
        
        # ============ Check 4: Suspicious TLDs in sender domain ============
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', '.download', '.live', '.win']
        for tld in suspicious_tlds:
            if actual_domain and actual_domain.endswith(tld):
                score += 20
                warnings.append(f"⚠️ Suspicious domain extension '{tld}' - commonly used by scammers")
                break
        
        # ============ Check 5: Domain contains numbers ============
        if actual_domain and re.search(r'\d+', actual_domain):
            if not any(legit in actual_domain for legit in ['safaricom', 'paypal', 'amazon']):
                score += 10
                warnings.append(f"⚠️ Sender domain contains numbers: '{actual_domain}' - often used by scammers")
        
        score = min(100, score)
        
        return {
            'score': score,
            'warnings': warnings,
            'headers_analyzed': list(headers.keys()),
            'display_name': display_name,
            'sender_domain': actual_domain,
            'reply_to_mismatch': bool(reply_to and actual_domain and reply_to_domain != actual_domain) if reply_to and actual_domain else False,
            'from_header': from_header[:100] if from_header else None
        }
        
    def analyze_email_headers_enhanced(self, email_text):
        """Enhanced email header analysis - detects more spoofing techniques"""
        
        headers = self.extract_email_headers(email_text)
        warnings = []
        score = 0
        
        from_header = headers.get('from', '')
        reply_to = headers.get('reply_to', '')
        return_path = headers.get('return_path', '')
        sender = headers.get('sender', '')
        
        # Check 1: Multiple @ symbols in From (spoofing)
        if from_header.count('@') > 1:
            score += 30
            warnings.append("🔴 Multiple email addresses in From header - spoofing attempt!")
        
        # Check 2: Display name with legitimate company but fake domain
        name_email_match = re.search(r'"([^"]+)"\s*<([^>]+)>', from_header)
        if not name_email_match:
            name_email_match = re.search(r'([^<]+)\s*<([^>]+)>', from_header)
        
        if name_email_match:
            display_name = name_email_match.group(1).strip()
            actual_email = name_email_match.group(2).strip()
            actual_domain = actual_email.split('@')[-1] if '@' in actual_email else ''
            
            legitimate_companies = ['Safaricom', 'M-Pesa', 'Airtel', 'Telkom', 'Equity', 
                                    'KCB', 'PayPal', 'Amazon', 'Microsoft', 'Apple', 
                                    'Netflix', 'DHL', 'FedEx', 'UPS', 'Bank', 'Chase']
            
            for company in legitimate_companies:
                if company.lower() in display_name.lower():
                    if actual_domain and actual_domain not in self.legitimate_domains:
                        score += 40
                        warnings.append(f"🔴 SPOOFING: Display name '{company}' but email from '{actual_domain}'")
                    break
        
        # Check 3: Return-Path mismatch
        if return_path and from_header:
            return_domain = return_path.split('@')[-1] if '@' in return_path else ''
            from_domain = from_header.split('@')[-1] if '@' in from_header else ''
            
            if return_domain and from_domain and return_domain != from_domain:
                score += 20
                warnings.append(f"⚠️ Return-Path domain '{return_domain}' doesn't match From domain '{from_domain}'")
        
        # Check 4: Sender header differs from From
        if sender and from_header:
            if sender != from_header:
                score += 15
                warnings.append("⚠️ Sender header differs from From header")
        
        # Check 5: Authentication-Results (if present)
        auth_results = headers.get('authentication-results', '')
        if auth_results:
            if 'fail' in auth_results.lower():
                score += 30
                warnings.append("🔴 Email authentication FAILED - this is a spoofed email!")
                if 'spf=fail' in auth_results.lower():
                    warnings.append("   SPF validation failed - sender not authorized")
                if 'dkim=fail' in auth_results.lower():
                    warnings.append("   DKIM signature invalid - email was tampered with")
            elif 'pass' in auth_results.lower():
                score = max(0, score - 10)
                warnings.append("✓ Email authentication passed (DKIM/SPF valid)")
        
                return {
                    'score': min(100, score),
                    'warnings': warnings,
                    'headers_found': list(headers.keys()),
                    'from_domain': from_header.split('@')[-1] if '@' in from_header else None,
                    'has_auth_results': bool(auth_results),
                    'auth_passed': 'pass' in auth_results.lower() if auth_results else None,
                    'is_spoofed': score >= 40
                }

            def extract_sender_domain(self, email_text):
                """Extract just the sender's email domain from email headers"""
                
                # Look for From: header
                from_match = re.search(r'From:.*?<([^>]+)>', email_text, re.IGNORECASE)
                if not from_match:
                    from_match = re.search(r'From:\s*([^\s]+@[^\s]+)', email_text, re.IGNORECASE)
                
                if from_match:
                    email = from_match.group(1)
                    if '@' in email:
                        return email.split('@')[-1].lower()
                
                return None

    # ============ ATTACHMENT SCANNING ============
        
    # ============ ATTACHMENT SCANNING ============
    
    def extract_attachment_info(self, email_text):
        """Extract attachment information from email WITHOUT opening files"""
        
        attachments = []
        text_lower = email_text.lower()
        
        # Common attachment filename patterns
        attachment_patterns = [
            r'filename=["\']?([^"\'<>]+\.(exe|scr|bat|cmd|pif|vbs|js|ps1|jar|app|msi|dll))["\']?',
            r'name=["\']?([^"\'<>]+\.(exe|scr|bat|cmd|pif|vbs|js|ps1|jar|app|msi|dll))["\']?',
            r'([\w\-]+\.(exe|scr|bat|cmd|pif|vbs|js|ps1|jar|app|msi|dll))',
            r'filename=["\']?([^"\'<>]+\.(docm|xlsm|pptm|doc|docx|xls|xlsx|ppt|pptx|pdf))["\']?',
            r'name=["\']?([^"\'<>]+\.(docm|xlsm|pptm|doc|docx|xls|xlsx|ppt|pptx|pdf))["\']?',
            r'filename=["\']?([^"\'<>]+\.(zip|rar|7z|gz|tar|iso))["\']?',
            r'name=["\']?([^"\'<>]+\.(zip|rar|7z|gz|tar|iso))["\']?',
        ]
        
        # Check for attachment headers
        attachment_indicators = [
            'Content-Disposition: attachment',
            'Content-Type: application/octet-stream',
            'Content-Type: application/x-msdownload',
            'Content-Type: application/zip',
            'Content-Type: application/x-rar',
            '--=_NextPart_',
        ]
        
        for indicator in attachment_indicators:
            if indicator.lower() in text_lower:
                for pattern in attachment_patterns:
                    matches = re.findall(pattern, email_text, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            filename = match[0]
                        else:
                            filename = match
                        
                        ext = filename.split('.')[-1].lower() if '.' in filename else ''
                        attachments.append({
                            'filename': filename,
                            'extension': ext,
                            'suspicious': self._is_dangerous_attachment(ext, filename)
                        })
        
        # Also look for "Attachment" word followed by filename
        plain_text_attachments = re.findall(r'(?:attachment|attached|attaching)[\s:]+([^\s,.\n]+\.\w+)', text_lower, re.IGNORECASE)
        for att in plain_text_attachments:
            ext = att.split('.')[-1].lower() if '.' in att else ''
            if att not in [a['filename'] for a in attachments]:
                attachments.append({
                    'filename': att,
                    'extension': ext,
                    'suspicious': self._is_dangerous_attachment(ext, att)
                })
        
        # Remove duplicates
        unique_attachments = []
        seen = set()
        for att in attachments:
            if att['filename'] not in seen:
                seen.add(att['filename'])
                unique_attachments.append(att)
        
        return unique_attachments[:10]
    
    def _is_dangerous_attachment(self, extension, filename):
        """Check if attachment extension is dangerous"""
        
        critical_extensions = {
            'exe', 'scr', 'bat', 'cmd', 'pif', 'com', 'vbs', 'vbe', 'js', 'jse',
            'ps1', 'psm1', 'psd1', 'msi', 'msp', 'mst', 'jar', 'app', 'application'
        }
        
        high_risk_extensions = {
            'docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'ppam', 'sldm'
        }
        
        medium_risk_extensions = {
            'zip', 'rar', '7z', 'gz', 'tar', 'iso', 'img'
        }
        
        low_risk_extensions = {
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf'
        }
        
        # Check for double extensions
        if '.' in filename and filename.count('.') > 1:
            parts = filename.split('.')
            last_ext = parts[-1].lower()
            if last_ext in critical_extensions:
                return {
                    'risk': 'CRITICAL',
                    'level': 100,
                    'reason': f'Double extension detected! This file masquerades as {parts[-2]}.{last_ext} but is actually executable.',
                    'color': 'danger',
                    'emoji': '🔴'
                }
        
        if extension in critical_extensions:
            return {
                'risk': 'CRITICAL',
                'level': 90,
                'reason': f'Executable file (.{extension}) - this could contain malware or ransomware',
                'color': 'danger',
                'emoji': '🔴'
            }
        elif extension in high_risk_extensions:
            return {
                'risk': 'HIGH',
                'level': 70,
                'reason': f'Macro-enabled document (.{extension}) - can contain malicious macros',
                'color': 'danger',
                'emoji': '🟠'
            }
        elif extension in medium_risk_extensions:
            return {
                'risk': 'MEDIUM',
                'level': 40,
                'reason': f'Archive file (.{extension}) - can contain hidden malware',
                'color': 'warning',
                'emoji': '🟡'
            }
        elif extension in low_risk_extensions:
            return {
                'risk': 'LOW',
                'level': 15,
                'reason': f'Document file (.{extension}) - usually safe but can contain malicious links',
                'color': 'info',
                'emoji': '🔵'
            }
        else:
            return {
                'risk': 'UNKNOWN',
                'level': 25,
                'reason': f'Unknown file type (.{extension}) - be cautious',
                'color': 'warning',
                'emoji': '❓'
            }
    
    def analyze_attachments(self, email_text):
        """Analyze attachments in email WITHOUT opening them"""
        
        attachments = self.extract_attachment_info(email_text)
        
        if not attachments:
            return {
                'has_attachments': False,
                'count': 0,
                'warnings': [],
                'score': 0,
                'highest_risk': 'LOW',  # ← YOU NEED THIS LINE
                'attachments': []
            }
        
        warnings = []
        score = 0
        highest_risk = 'LOW'
        
        for att in attachments:
            if att['suspicious']:
                risk_info = att['suspicious']
                if isinstance(risk_info, dict):
                    score += risk_info['level']
                    warnings.append(f"{risk_info['emoji']} Attachment '{att['filename']}': {risk_info['reason']}")
                    
                    if risk_info['risk'] == 'CRITICAL':
                        highest_risk = 'CRITICAL'
                    elif risk_info['risk'] == 'HIGH' and highest_risk != 'CRITICAL':
                        highest_risk = 'HIGH'
                    elif risk_info['risk'] == 'MEDIUM' and highest_risk not in ['CRITICAL', 'HIGH']:
                        highest_risk = 'MEDIUM'
        
        return {
            'has_attachments': len(attachments) > 0,
            'count': len(attachments),
            'warnings': warnings[:5],
            'score': min(100, score),
            'highest_risk': highest_risk,
            'attachments': [{'name': a['filename'], 'risk': a['suspicious']['risk'] if a['suspicious'] else 'UNKNOWN'} for a in attachments[:5]]
        }

# Create singleton instance
_detector = EmailScamDetector()

# ============ MAIN DETECTION FUNCTION ============

def detect_email_scam(email_text, region=None):
    """Detect phishing attempts in emails - GLOBAL SCAM DETECTION (NO CLICKS)"""
    
    if not email_text or not email_text.strip():
        return {
            'score': 0,
            'risk_level': 'LOW RISK',
            'color': 'success',
            'emoji': '🟢',
            'message': 'No email content to analyze',
            'warnings': ['Please provide email content'],
            'recommendations': ['Paste the email content you want to analyze'],
            'original_message': '',
            'type': 'EMAIL'
        }
    
    text_lower = email_text.lower()
    score = 0
    warnings = []
    detected_scam_types = []
    
    # ============ EMAIL HEADER ANALYSIS (SPOOF DETECTION) ============
    header_analysis = _detector.analyze_email_headers(email_text)
    
    if header_analysis['score'] > 0:
        score += header_analysis['score']
        for warning in header_analysis['warnings']:
            if warning not in warnings:
                warnings.append(warning)
        if header_analysis['warnings']:
            detected_scam_types.append("Email Spoofing Attempt")
    
    # ============ BANKING & FINANCIAL SCAMS ============
    for pattern, description, points in _detector.banking_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"🏦 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ LOAN & CREDIT SCAMS ============
    for pattern, description, points in _detector.loan_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"💰 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ PRIZE & LOTTERY SCAMS ============
    for pattern, description, points in _detector.prize_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"🎁 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ TAX SCAMS ============
    for pattern, description, points in _detector.tax_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"📄 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ TECH SUPPORT SCAMS ============
    for pattern, description, points in _detector.tech_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"💻 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ DELIVERY & COURIER SCAMS ============
    for pattern, description, points in _detector.delivery_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"📦 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ EMPLOYMENT SCAMS ============
    for pattern, description, points in _detector.employment_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"💼 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ ROMANCE SCAMS ============
    for pattern, description, points in _detector.romance_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"💔 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ INVESTMENT SCAMS ============
    for pattern, description, points in _detector.investment_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"📈 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ SUBSCRIPTION SCAMS ============
    for pattern, description, points in _detector.subscription_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"📺 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ CHARITY SCAMS ============
    for pattern, description, points in _detector.charity_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"🤝 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ RENTAL SCAMS ============
    for pattern, description, points in _detector.rental_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"🏠 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ NIGERIAN PRINCE/419 SCAMS ============
    for pattern, description, points in _detector.nigerian_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"👑 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ INVOICE SCAMS ============
    for pattern, description, points in _detector.invoice_scams:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"📑 {description}")
            detected_scam_types.append(description)
            break
    
    # ============ REGION-SPECIFIC SCAMS ============
    if region:
        region_list = [region]
    else:
        region_list = ['africa', 'asia', 'europe', 'americas', 'australia', 'middle_east']
    
    for reg in region_list:
        if reg in _detector.region_scams:
            for pattern, description, points in _detector.region_scams[reg]:
                if re.search(pattern, text_lower):
                    score += points
                    warnings.append(f"🌍 {description} ({reg})")
                    detected_scam_types.append(description)
                    break
    
    # ============ GENERAL HIGH RISK PATTERNS ============
    high_risk_patterns = [
        (r'verify your account', 'Account verification phishing', 20),
        (r'verify.*identity', 'Identity verification scam', 18),
        (r'account.*suspended', 'Account suspension scam', 20),
        (r'account.*(locked|blocked|closed)', 'Account locked/blocked scam', 20),
        (r'unusual activity', 'Suspicious activity alert', 15),
        (r'update your (payment|billing|credit card)', 'Payment update scam', 20),
        (r'reset your password', 'Password reset scam', 15),
    ]
    
    for pattern, description, points in high_risk_patterns:
        if re.search(pattern, text_lower):
            if not any(d in detected_scam_types for d in [description]):
                score += points
                warnings.append(f"🔴 {description}")
                detected_scam_types.append(description)
                break
    
    # ============ GENERAL MEDIUM RISK PATTERNS ============
    medium_risk_patterns = [
        (r'click here', 'Requests clicking a link', 12),
        (r'urgent action required', 'Urgency tactic', 12),
        (r'immediate attention', 'Pressure tactic', 10),
        (r'within 24 hours', 'Time pressure', 10),
        (r'limited time', 'Limited time offer', 8),
        (r'dear (customer|user|client|member)', 'Generic greeting', 8),
        (r'security alert', 'Security alert scam', 12),
    ]
    
    for pattern, description, points in medium_risk_patterns:
        if re.search(pattern, text_lower):
            if not any(d in detected_scam_types for d in [description]):
                score += points
                warnings.append(f"🟡 {description}")
                detected_scam_types.append(description)
                break
    
    # ============ URL ANALYSIS ============
    urls = _detector.extract_links_safely(email_text)
    url_analyses = []
    dangerous_urls = []
    
    for url in urls:
        url_analysis = _detector.analyze_url_safely(url)
        url_analyses.append(url_analysis)
        
        if url_analysis['should_block']:
            dangerous_urls.append(url_analysis)
            score += url_analysis['score'] / 2
            warnings.append(f"🔗 Suspicious link: {url_analysis['domain']}")
    
    # ============ ATTACHMENT ANALYSIS ============
    attachment_analysis = _detector.analyze_attachments(email_text)
    
    if attachment_analysis['has_attachments']:
        score += attachment_analysis['score']
        for warning in attachment_analysis['warnings']:
            if warning not in warnings:
                warnings.append(warning)
        if attachment_analysis['highest_risk'] in ['CRITICAL', 'HIGH']:
            detected_scam_types.append("Suspicious Attachment Detected")
    
    # ============ SENDER ANALYSIS ============
    sender_patterns = [
        (r'from:.*@.*\.(tk|ml|ga|cf|xyz|top|click|download)', 'Suspicious sender domain (free TLD)', 15),
        (r'reply-to:.*@.*\..*', 'Mismatched Reply-To address', 12),
    ]
    
    for pattern, description, points in sender_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            score += points
            warnings.append(f"📧 {description}")
    
    # ============ ATTACHMENT KEYWORDS ============
    attachment_words = ['attachment', 'download', 'invoice', 'document', 'statement', 'bill']
    attachments_found = [word for word in attachment_words if word in text_lower]
    if attachments_found:
        score += 10
        warnings.append(f"📎 Email mentions attachments: {', '.join(attachments_found[:2])}")
    
    # ============ ENCODED CONTENT CHECKS ============
    if '%' in email_text and len(re.findall(r'%[0-9A-F]{2}', email_text)) > 3:
        score += 15
        warnings.append("⚠️ Contains URL encoding - hiding tactic")
    
    if 'base64' in text_lower:
        score += 12
        warnings.append("⚠️ Contains base64 encoding - possible hidden content")
    
    # ============ LEGITIMATE INDICATORS ============
    legitimate_indicators = [
        (r'transaction id|receipt no|reference number', 'Contains transaction reference', 10),
        (r'completed on|confirmed on', 'Shows completion status', 8),
        (r'your (balance|statement) is', 'Shows account information', 10),
        (r'transaction.*successful', 'Transaction success message', 10),
    ]
    
    for pattern, description, reduction in legitimate_indicators:
        if re.search(pattern, text_lower):
            score = max(0, score - reduction)
            warnings.append(f"✓ {description} (legitimate indicator)")
    
    # Cap score at 100
    score = min(100, score)
    
    # ============ GENERATE RECOMMENDATIONS ============
    recommendations = []
    
    if score >= 60:
        recommendations.append("🚨 DELETE this email immediately")
        recommendations.append("❌ DO NOT click any links or download attachments")
        recommendations.append("📧 Forward as suspicious to your local cybercrime unit")
        recommendations.append("🔒 Never share passwords, PINs, or codes via email")
    elif score >= 30:
        recommendations.append("⚠️ Verify with sender through official channels (phone call, not email)")
        recommendations.append("🔗 Hover over links to see real destination (in your email client)")
        recommendations.append("📞 Contact the company using official numbers from their website")
        recommendations.append("✅ Check sender's email address carefully for misspellings")
    else:
        recommendations.append("✅ Always check sender's email address before responding")
        recommendations.append("🔒 Never share sensitive information via email")
        recommendations.append("📧 When in doubt, contact the company through official channels")
    
    if dangerous_urls:
        recommendations.append("🔗 The suspicious links found in this email should NEVER be clicked")
    
    # ============ DETERMINE RISK LEVEL ============
    if score >= 60:
        risk_level = "HIGH RISK - PHISHING DETECTED"
        color = "danger"
        emoji = "🔴"
        message = "⚠️ This email shows strong phishing indicators! Do not click links, reply, or download attachments."
    elif score >= 30:
        risk_level = "MEDIUM RISK - SUSPICIOUS"
        color = "warning"
        emoji = "🟡"
        message = "⚠️ This email has suspicious elements. Verify through official channels before taking action."
    else:
        risk_level = "LOW RISK - LIKELY SAFE"
        color = "success"
        emoji = "🟢"
        message = "✅ No obvious phishing patterns detected. Always exercise caution with unexpected emails."
    
    # ============ BUILD FINAL RESULT ============
    result = {
        'score': score,
        'risk_level': risk_level,
        'color': color,
        'emoji': emoji,
        'message': message,
        'recommendations': recommendations[:5],
        'warnings': warnings[:12] if warnings else ["✅ No phishing indicators found"],
        'urls_found': len(urls),
        'suspicious_urls_count': len(dangerous_urls),
        'original_message': email_text[:200] + ('...' if len(email_text) > 200 else ''),
        'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'type': 'EMAIL',
        'safe_analysis': True,
        'scam_type': detected_scam_types[0] if detected_scam_types else None,
        'global_analysis': True,
        'header_analysis': {
            'sender_domain': header_analysis.get('sender_domain'),
            'display_name': header_analysis.get('display_name'),
            'reply_to_mismatch': header_analysis.get('reply_to_mismatch', False),
            'spoof_warnings_count': len(header_analysis.get('warnings', []))
        },
        'attachment_analysis': {
            'has_attachments': attachment_analysis['has_attachments'],
            'count': attachment_analysis['count'],
            'highest_risk': attachment_analysis['highest_risk'],
            'warnings': attachment_analysis['warnings'][:3]
        }
    }
    
    if url_analyses:
        result['url_analyses'] = url_analyses[:5]
    
    return result


def detect_email_phishing(email_text):
    """Alias for detect_email_scam"""
    return detect_email_scam(email_text)


def get_scam_categories():
    """Return all scam categories for documentation"""
    return {
        'banking': [desc for _, desc, _ in _detector.banking_scams],
        'loan': [desc for _, desc, _ in _detector.loan_scams],
        'prize': [desc for _, desc, _ in _detector.prize_scams],
        'tax': [desc for _, desc, _ in _detector.tax_scams],
        'tech': [desc for _, desc, _ in _detector.tech_scams],
        'delivery': [desc for _, desc, _ in _detector.delivery_scams],
        'employment': [desc for _, desc, _ in _detector.employment_scams],
        'romance': [desc for _, desc, _ in _detector.romance_scams],
        'investment': [desc for _, desc, _ in _detector.investment_scams],
        'subscription': [desc for _, desc, _ in _detector.subscription_scams],
        'charity': [desc for _, desc, _ in _detector.charity_scams],
        'rental': [desc for _, desc, _ in _detector.rental_scams],
        'inheritance': [desc for _, desc, _ in _detector.nigerian_scams],
        'invoice': [desc for _, desc, _ in _detector.invoice_scams],
    }