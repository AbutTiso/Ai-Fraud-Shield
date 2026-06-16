# detector/sms_detector.py
"""
Context-Aware SMS Scam Detection Module
Detects scams in SMS messages with 200+ Kenyan-specific patterns
Understands that legitimate senders can use words found in scams
"""

import re
from datetime import datetime


class SMSScamDetector:
    """
    Context-aware SMS scam detection with comprehensive Kenyan patterns.
    Understands that words like 'verify', 'update', 'confirm' are safe
    when coming from known legitimate sources.
    """
    
    def __init__(self):
        self.version = "4.0"
        self.patterns_loaded = 0
        
        # ================================================================
        # CONTEXT-AWARE WORD ANALYSIS
        # These words are flagged ONLY in suspicious contexts,
        # NOT when they appear in legitimate messages
        # ================================================================
        self.context_dependent_words = {
            'verify': {
                'points': 20,
                'safe_with': ['mpesa_transaction', 'bank_notification', 'known_domain'],
                'examples_safe': [
                    'Verify your M-Pesa statement via *334#',
                    'KCB: Verify your account at any branch',
                ],
                'examples_scam': [
                    'Verify your PIN to claim prize',
                    'Click to verify your identity NOW',
                ],
            },
            'update': {
                'points': 18,
                'safe_with': ['bank_notification', 'service_notification', 'app_store'],
                'examples_safe': [
                    'Update your KCB mobile app from Play Store',
                    'System update available for your device',
                ],
                'examples_scam': [
                    'URGENT: Update your payment details now',
                    'Click to update your account information',
                ],
            },
            'confirm': {
                'points': 15,
                'safe_with': ['mpesa_transaction', 'bank_notification', 'appointment'],
                'examples_safe': [
                    'Confirm your M-Pesa transaction of Ksh 500',
                    'Please confirm your appointment for tomorrow',
                ],
                'examples_scam': [
                    'Confirm your PIN to receive money',
                    'Confirm identity with OTP now',
                ],
            },
            'free': {
                'points': 12,
                'safe_with': ['known_promotion', 'marketing', 'service_notification'],
                'examples_safe': [
                    'Free delivery on Jumia orders above Ksh 2000',
                    'Get free airtime when you recharge',
                ],
                'examples_scam': [
                    'FREE iPhone 15! Click to claim now!',
                    'Free money! Send Ksh 500 to receive Ksh 50000',
                ],
            },
            'offer': {
                'points': 10,
                'safe_with': ['known_promotion', 'marketing', 'bank_notification'],
                'examples_safe': [
                    'Special offer for Safaricom customers',
                    'Loan offer: Visit your nearest KCB branch',
                ],
                'examples_scam': [
                    'SPECIAL OFFER: Double your money today!',
                    'Limited offer: Send Ksh 1000 to claim',
                ],
            },
            'limited': {
                'points': 10,
                'safe_with': ['known_promotion', 'marketing'],
                'examples_safe': [
                    'Limited stock: Order now on Jumia',
                    'Limited time offer at Carrefour',
                ],
                'examples_scam': [
                    'LIMITED TIME: Send money to secure spot!',
                    'Limited slots available. Pay now!',
                ],
            },
            'claim': {
                'points': 15,
                'safe_with': ['mpesa_transaction', 'insurance', 'service_notification'],
                'examples_safe': [
                    'Claim your NHIF benefits at any branch',
                    'Claim your NSSF statement online',
                ],
                'examples_scam': [
                    'Claim your prize now! Send Ksh 1000',
                    'Claim your inheritance by sending your details',
                ],
            },
            'winner': {
                'points': 20,
                'safe_with': ['known_promotion'],  # Almost never safe in SMS
                'examples_safe': [
                    'You won 500 Bonga Points! Points credited to your account',
                ],
                'examples_scam': [
                    'WINNER! You won Ksh 500000! Send PIN to claim',
                    'Congratulations winner! Click to claim your prize',
                ],
            },
            'prize': {
                'points': 20,
                'safe_with': ['known_promotion'],  # Almost never safe in SMS
                'examples_safe': [
                    'Safaricom: Your Bonga Points prize of Ksh 1000 credited',
                ],
                'examples_scam': [
                    'You have won a prize! Send Ksh 500 to claim',
                    'Prize notification: Click http://scam.com to receive',
                ],
            },
            'account': {
                'points': 15,
                'safe_with': ['bank_notification', 'mpesa_transaction', 'service_notification'],
                'examples_safe': [
                    'Your account balance is Ksh 5000',
                    'Account statement ready for download',
                ],
                'examples_scam': [
                    'Your account will be BLOCKED! Verify now!',
                    'Account suspended due to unusual activity',
                ],
            },
            'security': {
                'points': 15,
                'safe_with': ['bank_notification', 'official_communication'],
                'examples_safe': [
                    'KCB: Security update for your mobile banking app',
                    'Visit kcbgroup.com/security for important updates',
                ],
                'examples_scam': [
                    'Security alert! Your account was hacked!',
                    'Security breach: Send OTP to secure account',
                ],
            },
            'login': {
                'points': 12,
                'safe_with': ['service_notification', 'app_notification'],
                'examples_safe': [
                    'New login detected on your Google account from Chrome',
                    'Login to your account at netflix.com',
                ],
                'examples_scam': [
                    'Suspicious login detected! Click http://fake.com to secure',
                    'Login attempt blocked. Verify at http://phishing.net',
                ],
            },
            'urgent': {
                'points': 25,
                'safe_with': [],  # Legitimate businesses rarely use "urgent" in SMS
                'examples_safe': [],
                'examples_scam': [
                    'URGENT: Your account suspended!',
                    'URGENT action required within 24 hours',
                ],
            },
            'suspended': {
                'points': 25,
                'safe_with': [],  # Almost never safe
                'examples_safe': [],
                'examples_scam': [
                    'Your M-Pesa account has been suspended',
                    'Account suspended: Verify now to restore',
                ],
            },
            'blocked': {
                'points': 20,
                'safe_with': ['service_notification'],  # e.g., "Your card blocked for security"
                'examples_safe': [
                    'KCB: Your card blocked for suspicious transaction. Call 0711047000',
                ],
                'examples_scam': [
                    'Your account BLOCKED! Call 0712345678 now!',
                    'Account blocked due to security breach',
                ],
            },
        }
        
        # ================================================================
        # KNOWN LEGITIMATE DOMAINS & SHORTCODES
        # Words associated with these are trusted
        # ================================================================
        self.safe_domains = {
            'safaricom.co.ke', 'safaricom.com', 'airtel.co.ke', 'telkom.co.ke',
            'kcbgroup.com', 'kcb.co.ke', 'equitybank.co.ke', 'coopbank.co.ke',
            'absabank.co.ke', 'stanbicbank.co.ke', 'ncbagroup.com',
            'kra.go.ke', 'ecitizen.go.ke', 'nssf.go.ke', 'nhif.go.ke',
            'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'whatsapp.com', 'telegram.org', 'youtube.com', 'wikipedia.org',
            'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
            'github.com', 'linkedin.com', 'zoom.us', 'paypal.com',
            'jumia.co.ke', 'kilimall.co.ke', 'carrefour.co.ke', 'naivas.co.ke',
        }
        
        self.safe_shortcodes = {
            '*334#', '*544#', '*100#', '*200#', '*456#', '*131#',
            '*144#', '*282#', '*444#', '*126#', '*188#', '*234#',
        }
        
        # ================================================================
        # SAFE CONTEXT PATTERNS — If message matches these, it's likely legitimate
        # ================================================================
        self.safe_context_patterns = {
            'mpesa_transaction': [
                r'm-pesa\s*:\s*ksh\s*\d[\d,]*\s+(?:to|from)\s+\w+\s+(?:successful|completed)',
                r'm-pesa\s*:\s*you\s+(?:received|sent)\s+ksh\s*\d+',
                r'm-pesa\s*:\s*(?:your\s+)?balance\s+(?:is|:)',
                r'm-pesa\s*:\s*transaction\s+(?:id|cost)\s+[a-z0-9]+',
                r'm-pesa\s*:\s*you\s+(?:bought|purchased)\s+(?:ksh\s*\d+\s+)?airtime',
            ],
            'bank_notification': [
                r'(?:kcb|equity|coop|absa|stanbic|ncba|family|dtb|ibl)\s*:',
                r'salary\s+(?:of\s+)?(?:ksh|kes)\s*\d+\s+credited',
                r'loan\s+(?:payment|repayment)\s+(?:of\s+)?(?:ksh|kes)\s*\d+\s+(?:received|processed)',
                r'standing\s+order\s+(?:of\s+)?(?:ksh|kes)\s*\d+\s+(?:processed|paid)',
                r'cheque\s+(?:book|deposited|cleared)',
                r'fixed\s+deposit\s+(?:matured|renewed)',
                r'(?:credited|debited)\s+(?:to|from)\s+(?:your\s+)?account',
            ],
            'service_notification': [
                r'(?:your\s+)?(?:data\s+bundle|airtime|subscription)\s+(?:expir|renew|ready)',
                r'(?:your\s+)?(?:bill|statement|invoice)\s+(?:is\s+ready|available|due|generated)',
                r'(?:appointment|booking|reservation)\s+(?:confirmed|reminder|scheduled)',
                r'(?:flight|train|bus|sgr)\s+(?:booking|ticket|departure|arrival)',
                r'(?:your\s+)?(?:order|package|delivery|parcel)\s+(?:confirmed|dispatched|arriving|delivered)',
                r'dial\s+\*\d+\#',
            ],
            'personal_message': [
                r'^(?:hi|hello|hey|habari|niaje|vipi|sasa|mambo)\b',
                r'\b(?:please|pls|kindly|tafadhali)\b.*\b(?:send|share|tell|bring|pick|buy|call|come)\b',
                r'\b(?:meeting|dinner|lunch|party|wedding|church|prayer|service|mkutano)\b',
                r'\b(?:happy\s+birthday|congratulations|pole|get\s+well|pongezi|rambirambi)\b',
                r'\b(?:home|house|school|office|work|nyumbani|shule|kazi)\b',
                r'\b(?:mom|dad|mum|baba|mama|sister|brother|kaka|dada|uncle|cousin)\b',
            ],
        }
    
            # ============ SCAM INDICATORS ============
        self.scam_indicators = {
            'high_risk': {
                'keywords': [
                    'urgent', 'immediately', 'suspended', 'locked', 'blocked',
                    'haraka', 'kufungiwa', 'zuiliwa', 'fungwa', 'sijasajiliwa',
                    'hatari', 'account will be closed', 'legal action',
                    'police case', 'arrest warrant', 'deactivate', 'unauthorized',
                ],
                'weight': 25,
            },
            'medium_risk': {
                'keywords': [
                    'click', 'link', 'send money', 'tuma pesa', 'mpesa', 'winner',
                    'congratulations', 'prize', 'free', 'claim', 'shinda', 'tuzo',
                    'cash', 'reward', 'gift', 'bonus', 'promotion', 'offer',
                    'limited time', 'exclusive', 'discount', 'free gift', 'bonyeza',
                    'kiungo', 'zawadi', 'pesa', 'hela', 'mshindi', 'ushindi',
                ],
                'weight': 10,
            }
        }
        
    def _analyze_context(self, text):
        """
        Analyze the context of a message.
        Returns dict with safe context flags.
        """
        text_lower = text.lower()
        
        context = {
            'is_mpesa_transaction': False,
            'is_bank_notification': False,
            'is_service_notification': False,
            'is_personal_message': False,
            'has_safe_url': False,
            'has_suspicious_url': False,
            'has_pin_request': False,
            'has_urgency': False,
            'has_fee_request': False,
            'has_threat': False,
            'has_unknown_phone': False,
            'safe_context_count': 0,
            'danger_signal_count': 0,
        }
        
        # Check safe contexts
        for context_name, patterns in self.safe_context_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    context[f'is_{context_name}'] = True
                    context['safe_context_count'] += 1
                    break
        
        # Check URLs
        urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+|www\.[^\s<>"\'{}|\\^`\[\]]+', text_lower)
        for url in urls:
            # Check if URL contains a safe domain
            url_clean = re.sub(r'^www\.|https?://', '', url).split('/')[0].lower()
            if url_clean in self.safe_domains or any(d in url_clean for d in self.safe_domains):
                context['has_safe_url'] = True
                context['safe_context_count'] += 2
            else:
                # Check for suspicious TLDs
                for tld in ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click']:
                    if tld in url:
                        context['has_suspicious_url'] = True
                        context['danger_signal_count'] += 3
                        break
        
        # Check for PIN/OTP requests (almost always dangerous)
        if re.search(r'(?:send|share|provide|enter|type|give|tuma)\s+(?:your\s+)?(?:pin|otp|mpin|password|secret|siri)', text_lower):
            context['has_pin_request'] = True
            context['danger_signal_count'] += 10
        
        # Check for urgency
        if re.search(r'urgent|immediately|asap|haraka|sasa\s+hivi|right\s+now|hatua\s+ya\s+haraka', text_lower):
            context['has_urgency'] = True
            context['danger_signal_count'] += 4
        
        # Check for fee requests
        if re.search(r'pay\s+(?:ksh|kes)\s*\d+|send\s+(?:ksh|kes)\s*\d+|processing\s+fee|registration\s+fee|lipa\s+ksh', text_lower):
            context['has_fee_request'] = True
            context['danger_signal_count'] += 5
        
        # Check for threats
        if re.search(r'suspended|blocked|locked|deactivated|closed|terminated|legal\s+action|police\s+case|fungwa|zuiwa', text_lower):
            context['has_threat'] = True
            context['danger_signal_count'] += 4
        
        # Check for unknown phone numbers
        if re.search(r'\b(07|01|2547)\d{8}\b', text_lower):
            # Check if it's in a safe context (like M-Pesa transaction with reference)
            if not context['is_mpesa_transaction'] and not context['is_bank_notification']:
                context['has_unknown_phone'] = True
                context['danger_signal_count'] += 2
        
        return context
    
    def _is_word_safe_in_context(self, word, context):
        """
        Determine if a context-dependent word is safe based on current context.
        """
        if word not in self.context_dependent_words:
            return False
        
        word_info = self.context_dependent_words[word]
        safe_contexts = word_info.get('safe_with', [])
        
        for safe_ctx in safe_contexts:
            if safe_ctx == 'mpesa_transaction' and context['is_mpesa_transaction']:
                return True
            if safe_ctx == 'bank_notification' and context['is_bank_notification']:
                return True
            if safe_ctx == 'service_notification' and context['is_service_notification']:
                return True
            if safe_ctx == 'known_domain' and context['has_safe_url']:
                return True
            if safe_ctx == 'known_promotion' and context['has_safe_url']:
                return True
            if safe_ctx == 'marketing' and (context['has_safe_url'] or context['is_service_notification']):
                return True
        
        return False
    
    def detect_sms_scam(self, sms_text):
        """Context-aware scam detection"""
        
        if not sms_text or not sms_text.strip():
            return self._get_empty_response()
        
        text_lower = sms_text.lower()
        score = 0
        warnings = []
        high_risk_found = []
        medium_risk_found = []
        legitimate_found = []
        context_adjustments = []
        recommendations = []
        
        # ============================================================
        # STEP 0: CONTEXT ANALYSIS (NEW!)
        # ============================================================
        context = self._analyze_context(sms_text)
        
        # If message is clearly from a safe context with no danger signals,
        # significantly reduce score
        if context['safe_context_count'] >= 2 and context['danger_signal_count'] == 0:
            score -= 30
            context_adjustments.append("✅ Safe context detected - score reduced")
        
        # ============================================================
        # SECTION 1: SCAM INDICATOR KEYWORDS (Context-aware)
        # ============================================================
        for keyword in self.scam_indicators['high_risk']['keywords']:
            if keyword in text_lower:
                # Check if this high-risk word is context-dependent
                if keyword in self.context_dependent_words:
                    if self._is_word_safe_in_context(keyword, context):
                        # Word is safe in this context — skip
                        context_adjustments.append(f"✅ '{keyword}' is safe in this context")
                        continue
                
                score += self.scam_indicators['high_risk']['weight']
                high_risk_found.append(keyword)
                warnings.append(f"⚠️ Uses high-risk keyword: '{keyword}'")
        
        for keyword in self.scam_indicators['medium_risk']['keywords']:
            if keyword in text_lower:
                if keyword in self.context_dependent_words:
                    if self._is_word_safe_in_context(keyword, context):
                        context_adjustments.append(f"✅ '{keyword}' is safe in this context")
                        continue
                
                score += self.scam_indicators['medium_risk']['weight']
                medium_risk_found.append(keyword)
                warnings.append(f"⚠️ Suspicious word: '{keyword}'")
        
        # ============================================================
        # SECTION 2: CATEGORIZED SCAM PATTERNS (161 patterns)
        # ============================================================
        
        # [All existing pattern categories remain the same]
        # ... (keeping all mpesa_scams, banking_scams, etc.) ...
        
        # For brevity, I'm keeping the existing pattern lists.
        # They're already well-structured and don't need context changes
        # since they're specific pattern matches.
        
        # ============================================================
        # SECTIONS 3-10: [KEEP ALL EXISTING CODE]
        # ============================================================
        # [All existing legitimate patterns, URL analysis, phone analysis,
        #  grammar checks, etc. remain exactly as they are]
        
        # ============================================================
        # CONTEXT-AWARE SCORE ADJUSTMENT
        # ============================================================
        # Apply context-based adjustments
        
        # Safe URL with known domain
        if context['has_safe_url']:
            score = max(0, score - 15)
            context_adjustments.append("✅ Contains link to known legitimate domain")
        
        # M-Pesa transaction context
        if context['is_mpesa_transaction'] and not context['has_pin_request']:
            score = max(0, score - 20)
            context_adjustments.append("✅ M-Pesa transaction format detected")
        
        # Bank notification context
        if context['is_bank_notification'] and not context['has_pin_request']:
            score = max(0, score - 20)
            context_adjustments.append("✅ Bank notification format detected")
        
        # Personal message context
        if context['is_personal_message'] and context['danger_signal_count'] < 3:
            score = max(0, score - 25)
            context_adjustments.append("✅ Personal message context detected")
        
        # Dangerous combinations increase score
        if context['has_pin_request']:
            score = min(100, score + 30)
            warnings.append("🔴 CRITICAL: Message requests PIN/OTP/password - this is NEVER legitimate!")
        
        if context['has_urgency'] and context['has_fee_request']:
            score = min(100, score + 20)
            warnings.append("🔴 Urgency + Money request = Classic scam pattern")
        
        # ============================================================
        # [KEEP ALL EXISTING FINAL LOGIC]
        # ============================================================
        # [Score capping, risk level determination, recommendations,
        #  and return dict remain exactly as they are]
        
        # Add context adjustments to warnings
        if context_adjustments:
            for adj in context_adjustments[:3]:
                if adj not in warnings:
                    legitimate_found.append(adj)
        
        # ... rest of existing code ...
        
        
        
        
                # ============================================================
        # SECTION 2: CATEGORIZED SCAM PATTERNS (161 patterns)
        # ============================================================
        
        # CATEGORY 1: M-PESA & Mobile Money Scams (15 patterns)
        mpesa_scams = [
            (r'm-pesa.*suspended', 'M-Pesa suspension scam', 20, 'HIGH'),
            (r'mpesa.*blocked', 'M-Pesa blocked account scam', 20, 'HIGH'),
            (r'fuliza.*limit.*increase', 'Fake Fuliza limit increase scam', 25, 'HIGH'),
            (r'm-shwari.*bonus', 'Fake M-Shwari bonus scam', 20, 'HIGH'),
            (r'm-pesa.*verify.*pin', 'M-Pesa PIN verification scam', 30, 'CRITICAL'),
            (r'mpesa.*upgrade.*required', 'Fake M-Pesa upgrade scam', 20, 'HIGH'),
            (r'm-pesa.*reward.*points', 'Fake M-Pesa reward points scam', 15, 'MEDIUM'),
            (r'mpesa.*transaction.*failed.*refund', 'Fake M-Pesa refund scam', 25, 'HIGH'),
            (r'mpesa.*account.*locked', 'M-Pesa account locked scam', 20, 'HIGH'),
            (r'm-pesa.*withdrawal.*alert', 'Fake M-Pesa withdrawal scam', 15, 'MEDIUM'),
            (r'mpesa.*cashback.*offer', 'Fake M-Pesa cashback scam', 15, 'MEDIUM'),
            (r'm-pesa.*lottery.*winner', 'M-Pesa lottery scam', 20, 'HIGH'),
            (r'fuliza.*loan.*approved', 'Fake Fuliza approval scam', 20, 'HIGH'),
            (r'm-shwari.*loan.*offer', 'Fake M-Shwari loan scam', 15, 'MEDIUM'),
            (r'm-pesa.*security.*alert', 'Fake M-Pesa security alert', 20, 'HIGH'),
        ]
        
        # CATEGORY 2: Banking Scams (20 patterns)
        banking_scams = [
            (r'kcb.*loan.*advance.*fee', 'Fake KCB loan advance fee scam', 25, 'HIGH'),
            (r'equity.*reward.*points', 'Fake Equity Bank reward scam', 15, 'MEDIUM'),
            (r'cooperative.*dividend', 'Fake Co-op Bank dividend scam', 15, 'MEDIUM'),
            (r'ncba.*loan.*offer', 'Fake NCBA loan offer scam', 15, 'MEDIUM'),
            (r'absa.*promotion.*winner', 'Fake Absa promotion scam', 15, 'MEDIUM'),
            (r'family.*bank.*loan', 'Fake Family Bank loan scam', 15, 'MEDIUM'),
            (r'kcb.*mpesa.*link', 'Fake KCB M-PESA link scam', 25, 'HIGH'),
            (r'equity.*mpesa.*integration', 'Fake Equity M-PESA integration scam', 25, 'HIGH'),
            (r'bank.*account.*suspended', 'Bank account suspension scam', 25, 'HIGH'),
            (r'bank.*verification.*required', 'Bank verification required scam', 20, 'HIGH'),
            (r'bank.*update.*details', 'Bank details update scam', 20, 'HIGH'),
            (r'bank.*security.*alert', 'Bank security alert scam', 20, 'HIGH'),
            (r'bank.*card.*blocked', 'Bank card blocked scam', 20, 'HIGH'),
            (r'bank.*loan.*approved', 'Fake bank loan approval scam', 15, 'MEDIUM'),
            (r'bank.*reward.*points', 'Fake bank reward points scam', 12, 'MEDIUM'),
            (r'stanbic.*alert', 'Fake Stanbic alert', 20, 'HIGH'),
            (r'standard.*chartered.*update', 'Fake Standard Chartered scam', 20, 'HIGH'),
            (r'dtb.*account.*verify', 'Fake DTB verification', 20, 'HIGH'),
            (r'ibl.*bank.*offer', 'Fake IBL Bank offer', 15, 'MEDIUM'),
            (r'bank.*of.*baroda.*lottery', 'Fake Bank of Baroda lottery', 20, 'HIGH'),
        ]
        
        # CATEGORY 3: Government Scams (20 patterns)
        government_scams = [
            (r'huduma.*number.*update', 'Fake Huduma Namba update scam', 25, 'HIGH'),
            (r'nssf.*refund.*claim', 'Fake NSSF refund scam', 25, 'HIGH'),
            (r'nhif.*medical.*upgrade', 'Fake NHIF upgrade scam', 25, 'HIGH'),
            (r'kra.*tax.*refund', 'Fake KRA tax refund scam', 30, 'HIGH'),
            (r'ecitizen.*account.*suspended', 'Fake eCitizen suspension scam', 25, 'HIGH'),
            (r'hef.*loan.*grant', 'Fake HELB loan scam', 25, 'HIGH'),
            (r'laptrust.*refund.*claim', 'Fake Laptrust refund scam', 20, 'MEDIUM'),
            (r'ntsa.*fine.*penalty', 'Fake NTSA fine scam', 25, 'HIGH'),
            (r'nema.*fine.*violation', 'Fake NEMA fine scam', 20, 'MEDIUM'),
            (r'kenya.*power.*disconnect', 'Fake Kenya Power disconnection scam', 25, 'HIGH'),
            (r'kcca.*fine.*penalty', 'Fake county fine scam', 20, 'MEDIUM'),
            (r'government.*grant.*winner', 'Fake government grant scam', 25, 'HIGH'),
            (r'presidential.*bailout.*fund', 'Fake presidential bailout scam', 30, 'CRITICAL'),
            (r'ura.*tax.*refund', 'Fake URA (Uganda) tax scam', 25, 'HIGH'),
            (r'ecitizen.*login.*verify', 'Fake eCitizen login scam', 25, 'HIGH'),
            (r'economic.*stimulus.*program', 'Fake stimulus program', 25, 'HIGH'),
            (r'inuarisha.*bidii', 'Fake Inuarisha program', 20, 'HIGH'),
            (r'hustler.*fund.*loan', 'Fake Hustler Fund scam', 25, 'HIGH'),
            (r'social.*protection.*fund', 'Fake social protection scam', 25, 'HIGH'),
            (r'cash.*transfer.*government', 'Fake government cash transfer', 25, 'HIGH'),
        ]
        
        # CATEGORY 4: Employment & Job Scams (15 patterns)
        employment_scams = [
            (r'kazi.*mtaani.*payment', 'Fake Kazi Mtaani payment scam', 30, 'CRITICAL'),
            (r'internship.*fee.*required', 'Fake internship fee scam', 25, 'HIGH'),
            (r'job.*application.*fee', 'Job application fee scam', 25, 'HIGH'),
            (r'work.*home.*earn.*money', 'Fake work from home scam', 20, 'HIGH'),
            (r'data.*entry.*job.*payment', 'Fake data entry job scam', 20, 'HIGH'),
            (r'online.*business.*opportunity', 'Fake online business scam', 20, 'HIGH'),
            (r'foreign.*job.*visa.*fee', 'Fake foreign job scam', 25, 'HIGH'),
            (r'airline.*job.*recruitment', 'Fake airline job scam', 20, 'MEDIUM'),
            (r'government.*job.*shortlist', 'Fake government job scam', 25, 'HIGH'),
            (r'career.*fair.*registration', 'Fake career fair scam', 15, 'MEDIUM'),
            (r'graduate.*internship.*program', 'Fake graduate internship scam', 20, 'MEDIUM'),
            (r'job.*offer.*processing.*fee', 'Job offer processing fee scam', 25, 'HIGH'),
            (r'cv.*update.*submit.*link', 'Fake CV update scam', 20, 'HIGH'),
            (r'remote.*job.*registration.*fee', 'Fake remote job scam', 20, 'HIGH'),
            (r'urgent.*hiring.*send.*cv', 'Fake urgent hiring scam', 20, 'HIGH'),
        ]
        
        # CATEGORY 5: Prize & Lottery Scams (12 patterns)
        prize_scams = [
            (r'won.*prize.*money', 'Prize scam', 20, 'HIGH'),
            (r'congratulations.*selected', 'Congratulations scam', 15, 'MEDIUM'),
            (r'safaricom.*promotion.*winner', 'Fake Safaricom promotion scam', 25, 'HIGH'),
            (r'airtel.*promotion.*winner', 'Fake Airtel promotion scam', 25, 'HIGH'),
            (r'telkom.*promotion.*winner', 'Fake Telkom promotion scam', 25, 'HIGH'),
            (r'lotto.*winner.*claim', 'Fake lottery winner scam', 25, 'HIGH'),
            (r'shell.*points.*prize', 'Fake Shell points scam', 20, 'MEDIUM'),
            (r'facebook.*lottery.*winner', 'Fake Facebook lottery scam', 20, 'MEDIUM'),
            (r'google.*promotion.*winner', 'Fake Google promotion scam', 20, 'MEDIUM'),
            (r'compensation.*payout.*claim', 'Fake compensation scam', 30, 'CRITICAL'),
            (r'inheritance.*claim.*payment', 'Fake inheritance scam', 30, 'CRITICAL'),
            (r'win.*car.*house.*prize', 'Fake car/house prize scam', 25, 'HIGH'),
        ]
        
        # CATEGORY 6: Emergency & Family Scams (12 patterns)
        emergency_scams = [
            (r'urgent.*send.*money', 'Urgent money request', 15, 'HIGH'),
            (r'accident.*hospital.*money', 'Fake accident emergency scam', 30, 'CRITICAL'),
            (r'family.*emergency.*money', 'Fake family emergency scam', 30, 'CRITICAL'),
            (r'child.*sick.*hospital.*money', 'Fake child sickness scam', 30, 'CRITICAL'),
            (r'kidnapped.*ransom.*money', 'Fake kidnapping ransom scam', 35, 'CRITICAL'),
            (r'police.*arrest.*bail.*money', 'Fake police arrest scam', 25, 'HIGH'),
            (r'stuck.*stranded.*money', 'Fake travel emergency scam', 20, 'HIGH'),
            (r'boss.*emergency.*transfer', 'Fake boss emergency transfer scam', 25, 'HIGH'),
            (r'pastor.*offering.*seed.*money', 'Fake church offering scam', 15, 'MEDIUM'),
            (r'prayer.*request.*money', 'Fake prayer request money scam', 12, 'MEDIUM'),
            (r'mtoto.*mgonjwa.*hospitali', 'Sick child scam (Swahili)', 30, 'CRITICAL'),
            (r'ajali.*tuma.*pesa', 'Accident send money (Swahili)', 30, 'CRITICAL'),
        ]
        
        # CATEGORY 7: Investment Scams (10 patterns)
        investment_scams = [
            (r'forex.*guaranteed.*profit', 'Fake Forex guaranteed profit scam', 30, 'CRITICAL'),
            (r'crypto.*mining.*investment', 'Fake crypto mining scam', 30, 'CRITICAL'),
            (r'stock.*insider.*trading', 'Fake stock trading scam', 25, 'HIGH'),
            (r'chama.*investment.*dividend', 'Fake chama investment scam', 20, 'MEDIUM'),
            (r'sacco.*shares.*dividend', 'Fake SACCO shares scam', 20, 'MEDIUM'),
            (r'mlm.*business.*opportunity', 'Fake MLM business scam', 25, 'HIGH'),
            (r'pyramid.*scheme.*investment', 'Pyramid scheme scam', 35, 'CRITICAL'),
            (r'land.*investment.*cheap', 'Fake land investment scam', 20, 'HIGH'),
            (r'gold.*investment.*returns', 'Fake gold investment scam', 25, 'HIGH'),
            (r'bitcoin.*investment.*double', 'Fake Bitcoin doubling scam', 30, 'CRITICAL'),
        ]
        
        # CATEGORY 8: Threat & Pressure Tactics (12 patterns)
        threat_scams = [
            (r'account.*blocked.*verify', 'Account blocked scam', 20, 'HIGH'),
            (r'your account.*suspended', 'Account suspension scam', 20, 'HIGH'),
            (r'limited time.*offer', 'Urgency tactic', 10, 'LOW'),
            (r'final.*warning.*notice', 'Final warning scam', 20, 'HIGH'),
            (r'legal.*action.*against.*you', 'Legal action threat scam', 25, 'HIGH'),
            (r'court.*case.*file', 'Court case threat scam', 20, 'HIGH'),
            (r'last.*chance.*offer', 'Last chance pressure scam', 15, 'MEDIUM'),
            (r'within.*24.*hours.*action', 'Time pressure scam', 15, 'MEDIUM'),
            (r'expires.*today.*offer', 'Expiring offer scam', 15, 'MEDIUM'),
            (r'immediate.*action.*required', 'Immediate action scam', 20, 'HIGH'),
            (r'will.*be.*deactivated', 'Deactivation threat scam', 20, 'HIGH'),
            (r'will.*be.*closed.*permanently', 'Permanent closure threat', 20, 'HIGH'),
        ]
        
        # CATEGORY 9: Phishing & Link Scams (10 patterns)
        phishing_scams = [
            (r'click.*link.*verify', 'Verification link scam', 15, 'MEDIUM'),
            (r'verify.*identity.*link', 'Identity verification scam', 15, 'MEDIUM'),
            (r'update.*payment.*details', 'Payment update scam', 15, 'MEDIUM'),
            (r'confirm.*account.*details', 'Account confirmation scam', 15, 'MEDIUM'),
            (r'login.*verify.*account', 'Login verification scam', 15, 'MEDIUM'),
            (r'secure.*your.*account', 'Account security scam', 12, 'MEDIUM'),
            (r'validate.*your.*details', 'Details validation scam', 12, 'MEDIUM'),
            (r'update.*your.*information', 'Information update scam', 12, 'MEDIUM'),
            (r'reactivate.*your.*account', 'Account reactivation scam', 15, 'MEDIUM'),
            (r'unlock.*your.*account', 'Account unlock scam', 15, 'MEDIUM'),
        ]
        
        # CATEGORY 10: Swahili Scams (20 patterns)
        swahili_scams = [
            (r'akaunti.*yako.*imefungwa', 'Account blocked (Swahili)', 25, 'HIGH'),
            (r'tuma.*pesa.*sasa.*haraka', 'Send money urgently (Swahili)', 25, 'HIGH'),
            (r'umeshinda.*tuzo.*pesa', 'You won prize (Swahili)', 25, 'HIGH'),
            (r'namba.*yako.*siri.*toa', 'Share your PIN (Swahili)', 35, 'CRITICAL'),
            (r'benki.*yako.*imefungwa', 'Bank blocked (Swahili)', 25, 'HIGH'),
            (r'mkopo.*wako.*umekubaliwa', 'Loan approved (Swahili)', 20, 'HIGH'),
            (r'malipo.*yako.*imeshindwa', 'Payment failed (Swahili)', 20, 'HIGH'),
            (r'bonyeza.*hapa.*kiungo', 'Click link (Swahili)', 15, 'MEDIUM'),
            (r'thibitisha.*namba.*yako.*siri', 'Verify PIN (Swahili)', 35, 'CRITICAL'),
            (r'mtoto.*mgonjwa.*hospitali', 'Sick child hospital (Swahili)', 30, 'CRITICAL'),
            (r'ajali.*ime.*tokea.*tuma.*pesa', 'Accident send money (Swahili)', 30, 'CRITICAL'),
            (r'kazi.*ya.*nyumbani.*pata.*pesa', 'Work from home (Swahili)', 20, 'HIGH'),
            (r'fedha.*za.*serikali.*kukusaidia', 'Govt money help (Swahili)', 25, 'HIGH'),
            (r'shiriki.*na.*ushinde.*zawadi', 'Win prize (Swahili)', 20, 'HIGH'),
            (r'hatua.*ya.*haraka.*inahitajika', 'Urgent action (Swahili)', 20, 'HIGH'),
            (r'tuma.*hela.*haraka', 'Send money fast (Swahili slang)', 25, 'HIGH'),
            (r'fungua.*akaunti.*link', 'Open account link (Swahili)', 20, 'HIGH'),
            (r'kadi.*yako.*imezuiwa', 'Card blocked (Swahili)', 25, 'HIGH'),
            (r'ombi.*lako.*limekubaliwa', 'Application approved (Swahili)', 15, 'MEDIUM'),
            (r'pata.*mkopo.*haraka', 'Get loan fast (Swahili)', 20, 'HIGH'),
        ]
        
        # CATEGORY 11: Brand Impersonation (15 patterns)
        brand_impersonation = [
            (r'safaricom.*?(win|prize|reward|promotion)', 'Fake Safaricom promotion', 20, 'HIGH'),
            (r'airtel.*?(win|prize|reward|promotion)', 'Fake Airtel promotion', 20, 'HIGH'),
            (r'telkom.*?(win|prize|reward|promotion)', 'Fake Telkom promotion', 20, 'HIGH'),
            (r'kcb.*?(win|prize|loan|reward)', 'Fake KCB offer', 20, 'HIGH'),
            (r'equity.*?(win|prize|reward|points)', 'Fake Equity Bank offer', 20, 'HIGH'),
            (r'coop.*?(win|prize|dividend)', 'Fake Co-op Bank offer', 20, 'HIGH'),
            (r'absa.*?(win|prize|reward)', 'Fake Absa Bank offer', 20, 'HIGH'),
            (r'dhl.*?delivery.*?fee', 'Fake DHL delivery fee', 20, 'HIGH'),
            (r'fedex.*?package.*?fee', 'Fake FedEx package fee', 20, 'HIGH'),
            (r'posta.*?delivery.*?fee', 'Fake Posta delivery fee', 20, 'HIGH'),
            (r'microsoft.*?virus.*?alert', 'Fake Microsoft alert', 22, 'HIGH'),
            (r'apple.*?security.*?warning', 'Fake Apple security warning', 22, 'HIGH'),
            (r'google.*?verification.*?required', 'Fake Google verification', 20, 'HIGH'),
            (r'facebook.*?account.*?suspended', 'Fake Facebook suspension', 20, 'HIGH'),
            (r'whatsapp.*?violation.*?policy', 'Fake WhatsApp policy violation', 20, 'HIGH'),
        ]
        
        # ============================================================
        # COMBINE ALL PATTERNS AND CHECK
        # ============================================================
        all_scam_patterns = (mpesa_scams + banking_scams + government_scams + 
                             employment_scams + prize_scams + emergency_scams + 
                             investment_scams + threat_scams + phishing_scams + 
                             swahili_scams + brand_impersonation)
        
        self.patterns_loaded = len(all_scam_patterns)
        
        for pattern, description, points, severity in all_scam_patterns:
            if re.search(pattern, text_lower):
                # For context-dependent words in patterns, check context
                should_skip = False
                if not context['has_pin_request'] and not context['has_urgency']:
                    # If no dangerous signals and pattern matched in safe context
                    if context['is_bank_notification'] and 'bank' in description.lower():
                        should_skip = True
                    if context['is_mpesa_transaction'] and 'mpesa' in description.lower():
                        should_skip = True
                
                if not should_skip:
                    score += points
                    warning_msg = f"⚠️ {description}"
                    if warning_msg not in warnings:
                        warnings.append(warning_msg)
                        if severity in ('CRITICAL', 'HIGH'):
                            high_risk_found.append(description)
                        else:
                            medium_risk_found.append(description)
        
        # ============================================================
        # SECTION 3: LEGITIMATE PATTERNS (reduce score)
        # ============================================================
        legitimate_patterns = [
            (r'safaricom.*?transaction.*?ksh', 'Official M-Pesa transaction'),
            (r'received.*?ksh.*?from', 'Official receipt'),
            (r'transaction.*?successful', 'Transaction success'),
            (r'thank you for (using|shopping|banking)', 'Thank you message'),
            (r'dial \*334\#', 'Official M-PESA USSD code'),
            (r'receipt no\.?\s*[A-Z0-9]{6,}', 'Official receipt number'),
            (r'your (?:salary|loan payment) of ksh', 'Bank payment notification'),
            (r'new balance:?\s*ksh', 'Balance update'),
            (r'confirmation code:?\s*[A-Z0-9]+', 'Official confirmation code'),
            (r'\*544\#', 'Safaricom data bundle USSD'),
        ]
        
        for pattern, description in legitimate_patterns:
            if re.search(pattern, text_lower):
                legitimate_found.append(description)
                score = max(0, score - 10)
        
        # ============================================================
        # SECTION 4: URL ANALYSIS
        # ============================================================
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text_lower)
        if urls:
            # Only add URL warning if URL is NOT safe
            if not context['has_safe_url']:
                score += 12
                warnings.append(f"🔗 Suspicious link detected ({len(urls)} URL(s))")
            else:
                context_adjustments.append("✅ URL is from known legitimate domain")
            
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', '.live', '.win', '.bid', '.loan']
            for url in urls:
                # Skip safe URLs
                url_clean = re.sub(r'^www\.|https?://', '', url).split('/')[0].lower()
                if url_clean in self.safe_domains:
                    continue
                
                for tld in suspicious_tlds:
                    if tld in url:
                        score += 15
                        warnings.append(f"⚠️ Suspicious domain extension in link: {tld}")
                        break
                
                if re.search(r'\d+\.\d+\.\d+\.\d+', url):
                    score += 20
                    warnings.append("⚠️ Link uses IP address instead of domain name")
                
                shorteners = ['bit.ly', 'tinyurl.com', 'short.link', 'cutt.ly', 'ow.ly', 'is.gd', 'goo.gl']
                for shortener in shorteners:
                    if shortener in url:
                        score += 12
                        warnings.append(f"🔗 URL shortener detected ({shortener})")
                        break
        
        # ============================================================
        # SECTION 5: PHONE NUMBER ANALYSIS
        # ============================================================
        phone_numbers = re.findall(r'(07|01|2547)\d{8}', text_lower)
        if phone_numbers:
            unique_numbers = list(set(phone_numbers))
            
            # Don't flag phone numbers in M-Pesa transactions (they include sender numbers)
            if not context['is_mpesa_transaction']:
                score += 10
                warnings.append(f"📞 Unknown phone number(s): {', '.join(unique_numbers[:2])}")
            
            for number in unique_numbers:
                if re.search(r'(\d)\1{7,}', number):
                    score += 10
                    warnings.append(f"⚠️ Number has suspicious repeated digits: {number}")
        
        # ============================================================
        # SECTION 6: GRAMMAR & SPELLING ERRORS
        # ============================================================
        grammar_issues = 0
        common_mistakes = [
            'recieve', 'wich', 'thier', 'untill', 'definately', 
            'seperate', 'occured', 'priviledge', 'goverment', 'comission',
            'accomodate', 'maintainance', 'refferal', 'transfered', 'benifit',
            'recieved', 'adress', 'beleive', 'calender', 'cemetary',
        ]
        
        for mistake in common_mistakes:
            if mistake in text_lower:
                grammar_issues += 1
        
        if grammar_issues >= 2:
            score += grammar_issues * 3
            warnings.append(f"📝 Multiple spelling errors ({grammar_issues}) - common in scams")
        
        # ============================================================
        # SECTION 7: EXCLAMATION OVERUSE
        # ============================================================
        exclamation_count = text_lower.count('!')
        if exclamation_count >= 3:
            score += exclamation_count
            if exclamation_count >= 5:
                warnings.append(f"⚠️ Excessive exclamation marks ({exclamation_count}) - pressure tactic")
        
        # ============================================================
        # SECTION 8: MULTIPLE INDICATOR BONUS
        # ============================================================
        if len(warnings) >= 5:
            score += 15
            warnings.append(f"⚠️ Multiple scam indicators ({len(warnings)}) detected")
        
        # ============================================================
        # SECTION 9: DANGEROUS COMBINATIONS
        # ============================================================
        urgent_words = ['urgent', 'immediately', 'asap', 'haraka', 'sasa']
        money_words = ['money', 'pesa', 'send', 'tuma', 'transfer', 'pay', 'lipa']
        sensitive_words = ['pin', 'password', 'otp', 'code', 'siri', 'namba']
        
        urgency_present = any(w in text_lower for w in urgent_words)
        money_present = any(w in text_lower for w in money_words)
        sensitive_present = any(w in text_lower for w in sensitive_words)
        
        if urgency_present and money_present:
            score += 20
            warnings.append("🔴 CRITICAL: Urgency + Money request = Classic scam pattern")
        
        if urgency_present and sensitive_present:
            score += 30
            warnings.append("🔴 CRITICAL: PIN request combined with urgency - DEFINITE SCAM")
        
        if money_present and sensitive_present:
            score += 15
            warnings.append("🔴 Money request + Sensitive information request")
        
        # ============================================================
        # CONTEXT-AWARE SCORE ADJUSTMENT (FINAL)
        # ============================================================
        
        # Safe URL with known domain
        if context['has_safe_url']:
            score = max(0, score - 15)
            if "link to known legitimate domain" not in str(context_adjustments):
                context_adjustments.append("✅ Contains link to known legitimate domain")
        
        # M-Pesa transaction context without danger signals
        if context['is_mpesa_transaction'] and not context['has_pin_request'] and not context['has_urgency']:
            score = max(0, score - 20)
            if "M-Pesa transaction" not in str(context_adjustments):
                context_adjustments.append("✅ M-Pesa transaction format detected")
        
        # Bank notification context without danger signals
        if context['is_bank_notification'] and not context['has_pin_request'] and not context['has_urgency']:
            score = max(0, score - 20)
            if "Bank notification" not in str(context_adjustments):
                context_adjustments.append("✅ Bank notification format detected")
        
        # Personal message context
        if context['is_personal_message'] and context['danger_signal_count'] < 3:
            score = max(0, score - 25)
            if "Personal message" not in str(context_adjustments):
                context_adjustments.append("✅ Personal message context detected")
        
        # Service notification context
        if context['is_service_notification'] and context['danger_signal_count'] < 2:
            score = max(0, score - 15)
            if "Service notification" not in str(context_adjustments):
                context_adjustments.append("✅ Service notification context detected")
        
        # Dangerous combinations INCREASE score
        if context['has_pin_request']:
            score = min(100, score + 30)
            if "PIN/OTP" not in str(warnings):
                warnings.append("🔴 CRITICAL: Message requests PIN/OTP/password - this is NEVER legitimate!")
        
        if context['has_urgency'] and context['has_fee_request']:
            score = min(100, score + 20)
        
        if context['has_threat'] and context['has_unknown_phone']:
            score = min(100, score + 15)
        
        # ============================================================
        # SCORE CAPPING & DEDUP
        # ============================================================
        score = min(100, max(0, score))
        warnings = list(dict.fromkeys(warnings))
        
        # ============================================================
        # GENERATE RECOMMENDATIONS
        # ============================================================
        if high_risk_found or context['has_pin_request']:
            recommendations.append("🚨 DO NOT reply to this message or click any links")
            recommendations.append("📞 Contact your service provider directly using official numbers")
            recommendations.append("🚫 Never share your PIN, password, or M-Pesa code")
        
        if medium_risk_found:
            recommendations.append("🔍 Verify the sender by calling official customer care")
            recommendations.append("📱 Report suspicious messages to 333 (Safaricom) or 3333 (Airtel)")
        
        if urls and not context['has_safe_url']:
            recommendations.append("🔗 Hover over links to see real destination before clicking")
        
        if phone_numbers and not context['is_mpesa_transaction']:
            recommendations.append("📞 Don't call back unknown numbers - scammers use premium rates")
        
        if sensitive_present or context['has_pin_request']:
            recommendations.append("🔐 NEVER share your PIN - legitimate companies will NEVER ask for it")
        
        if not high_risk_found and not medium_risk_found and score < 15:
            recommendations.append("✅ This message appears safe based on context analysis")
            recommendations.append("🔐 Always verify unexpected requests through official channels")
        
        # ============================================================
        # DETERMINE RISK LEVEL
        # ============================================================
        if score >= 75:
            risk_level = "CRITICAL - SCAM CONFIRMED"
            risk_level_display = "CRITICAL"
            color = "danger"
            badge_class = "bg-danger"
            emoji = "🔴🚨"
            message = "🔴 CRITICAL: This SMS is a CONFIRMED SCAM! DO NOT respond, click links, or send money!"
            is_scam = True
        elif score >= 60:
            risk_level = "HIGH RISK - SCAM DETECTED"
            risk_level_display = "HIGH"
            color = "danger"
            badge_class = "bg-danger"
            emoji = "🔴"
            message = "⚠️ HIGH RISK: This SMS shows strong scam indicators! Do not click links or send money."
            is_scam = True
        elif score >= 35:
            risk_level = "MEDIUM RISK - SUSPICIOUS"
            risk_level_display = "MEDIUM"
            color = "warning"
            badge_class = "bg-warning"
            emoji = "🟡"
            message = "⚠️ MEDIUM RISK: This SMS has suspicious elements. Verify through official channels."
            is_scam = False
        elif score >= 15:
            risk_level = "LOW RISK - CAUTION"
            risk_level_display = "LOW"
            color = "info"
            badge_class = "bg-info"
            emoji = "🔵"
            message = "🔵 LOW RISK: Minor suspicious elements detected. Be cautious."
            is_scam = False
        else:
            risk_level = "LOW RISK - LIKELY SAFE"
            risk_level_display = "LOW"
            color = "success"
            badge_class = "bg-success"
            emoji = "🟢"
            message = "✅ LOW RISK: No obvious scam patterns detected. This message appears safe."
            is_scam = False
        
        # ============================================================
        # RETURN RESULT
        # ============================================================
        return {
            'score': score,
            'risk_level': risk_level,
            'risk_level_display': risk_level_display,
            'color': color,
            'badge_class': badge_class,
            'emoji': emoji,
            'message': message,
            'is_scam': is_scam,
            'warnings': warnings[:10] if warnings else ["✅ No scam indicators found"],
            'recommendations': recommendations[:6],
            'high_risk_indicators': high_risk_found[:3],
            'medium_risk_indicators': medium_risk_found[:3],
            'indicators': {
                'high_risk': list(set(high_risk_found))[:3],
                'medium_risk': list(set(medium_risk_found))[:3],
                'legitimate_signs': legitimate_found[:2],
                'url_count': len(urls) if 'urls' in locals() else 0,
                'phone_count': len(phone_numbers) if 'phone_numbers' in locals() else 0,
                'grammar_issues': grammar_issues,
            },
            'urls_found': len(urls) if 'urls' in locals() else 0,
            'phones_found': len(phone_numbers) if 'phone_numbers' in locals() else 0,
            'grammar_issues': grammar_issues,
            'exclamation_count': exclamation_count,
            'original_preview': sms_text[:150] + ('...' if len(sms_text) > 150 else ''),
            'type': 'SMS',
            'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'context': {
                'safe_contexts': context['safe_context_count'],
                'danger_signals': context['danger_signal_count'],
                'is_bank_notification': context['is_bank_notification'],
                'is_mpesa_transaction': context['is_mpesa_transaction'],
                'is_personal_message': context['is_personal_message'],
                'has_safe_url': context['has_safe_url'],
                'context_adjustments': context_adjustments[:3],
            }
        }
    
    def _get_empty_response(self):
        """Return empty response for no input"""
        return {
            'score': 0,
            'risk_level': 'NO DATA',
            'risk_level_display': 'LOW',
            'color': 'secondary',
            'badge_class': 'bg-secondary',
            'emoji': '⚪',
            'message': 'No SMS content provided for analysis',
            'is_scam': False,
            'warnings': ['Please provide SMS text to analyze'],
            'recommendations': ['Enter an SMS message to check for scam indicators'],
            'high_risk_indicators': [],
            'medium_risk_indicators': [],
            'indicators': {'high_risk': [], 'medium_risk': [], 'legitimate_signs': [], 'url_count': 0, 'phone_count': 0, 'grammar_issues': 0},
            'urls_found': 0,
            'phones_found': 0,
            'grammar_issues': 0,
            'exclamation_count': 0,
            'type': 'SMS',
            'context': {'safe_contexts': 0, 'danger_signals': 0, 'context_adjustments': []},
        }


# Singleton instance
_detector = None

def get_detector():
    """Get or create singleton detector instance"""
    global _detector
    if _detector is None:
        _detector = SMSScamDetector()
    return _detector


def detect_sms_scam(sms_text):
    """
    Convenience function for SMS scam detection.
    Maintains backward compatibility with existing code.
    """
    detector = get_detector()
    return detector.detect_sms_scam(sms_text)


def quick_test():
    """Test the SMS detector with context-aware examples"""
    print("\n" + "="*60)
    print("📱 SMS Detector Quick Test (Context-Aware)")
    print("="*60)
    
    test_cases = [
        ("Normal M-Pesa", "M-Pesa: Ksh 500 to John successful. Balance: Ksh 2,500. Transaction cost: Ksh 27"),
        ("Bank Notification", "KCB: Salary Ksh 45000 credited to your account. New balance: Ksh 125000"),
        ("Personal Message", "Hi mom, can you pick up bread on your way home? Also please bring milk"),
        ("Suspicious Promotion", "CONGRATULATIONS! You've won 50,000 bonus points! Click https://bit.ly/claim now!"),
        ("Critical Scam", "URGENT! Your M-Pesa account has been suspended. Send your MPIN to 0712345678 for verification NOW!"),
        ("Swahili Scam", "Tuma pesa sasa haraka kwa namba 0711222333 ili kuthibitisha akaunti yako!"),
        ("Legit with 'verify' word", "KCB: Please verify your account details at any branch or visit kcbgroup.com/verify"),
        ("Scam with 'verify' word", "VERIFY YOUR ACCOUNT NOW! Click http://verify-scam.tk or your account will be BLOCKED!"),
        ("Legit with 'offer' word", "Jumia: Special offer! 50% off on electronics. Shop at jumia.co.ke/deals"),
        ("Scam with 'offer' word", "SPECIAL OFFER! Double your money in 24 hours! Send Ksh 5000 to 0711111111!"),
    ]
    
    detector = get_detector()
    
    for name, text in test_cases:
        print(f"\n📝 {name}:")
        print(f"   Text: {text[:80]}...")
        result = detector.detect_sms_scam(text)
        print(f"   Score: {result['score']}/100")
        print(f"   Risk: {result['risk_level_display']}")
        print(f"   Is Scam: {result['is_scam']}")
        if 'context' in result:
            ctx = result['context']
            print(f"   Safe Contexts: {ctx.get('safe_contexts', 0)} | Danger Signals: {ctx.get('danger_signals', 0)}")


if __name__ == "__main__":
    quick_test()


