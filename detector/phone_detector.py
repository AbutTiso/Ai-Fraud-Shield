# detector/phone_detector.py
"""
Context-Aware Phone Scam Detection Module
Understands that legitimate organizations can use words found in scams
when the call context is appropriate.
"""

import re
from datetime import datetime
import json
import os
from typing import Dict, List, Tuple, Optional


class PhoneScamDetector:
    """Advanced Context-Aware Phone Call Scam Detection"""
    
    def __init__(self):
        # ============ LEGITIMATE NUMBERS ============
        self.legitimate_numbers = {
            '0722000000': 'Safaricom Official', '0722000001': 'Safaricom Official',
            '0722000002': 'Safaricom Official', '0722000003': 'Safaricom Official',
            '100': 'Safaricom Customer Care', '200': 'Safaricom Customer Care',
            '333': 'Safaricom Scam Reporting', '3333': 'Airtel Scam Reporting',
            '150': 'Airtel Customer Care', '151': 'Airtel Customer Care',
            '123': 'Telkom Customer Care', '124': 'Telkom Customer Care',
            '0703070000': 'Equity Bank Official', '0711047000': 'KCB Official',
            '0711025000': 'Co-op Bank Official', '0703023000': 'Absa Bank Official',
            '112': 'Emergency Services', '911': 'Emergency Services', '999': 'Police Emergency',
        }
        
        # ============ CONTEXT-DEPENDENT WORDS ============
        # These words appear in BOTH scams and legitimate calls
        self.context_dependent_words = {
            'verify': {
                'points': 20,
                'safe_with': ['outbound_call_to_bank', 'outbound_call_to_telco', 'known_caller'],
                'dangerous_with': ['unsolicited_incoming', 'with_pin_request', 'with_urgency'],
            },
            'update': {
                'points': 15,
                'safe_with': ['outbound_call_to_bank', 'service_call'],
                'dangerous_with': ['unsolicited_incoming', 'with_pin_request'],
            },
            'confirm': {
                'points': 15,
                'safe_with': ['outbound_call_to_bank', 'transaction_verification'],
                'dangerous_with': ['unsolicited_incoming', 'with_pin_request'],
            },
            'account': {
                'points': 15,
                'safe_with': ['outbound_call_to_bank', 'known_caller'],
                'dangerous_with': ['unsolicited_incoming', 'with_threat', 'with_urgency'],
            },
            'security': {
                'points': 15,
                'safe_with': ['outbound_call_to_bank', 'known_caller'],
                'dangerous_with': ['unsolicited_incoming', 'with_pin_request'],
            },
            'suspended': {
                'points': 25,
                'safe_with': [],  # Almost never safe in incoming calls
                'dangerous_with': ['any_context'],
            },
            'urgent': {
                'points': 25,
                'safe_with': [],  # Legitimate businesses rarely use urgent
                'dangerous_with': ['any_context'],
            },
            'pin': {
                'points': 35,
                'safe_with': [],  # NEVER safe - no legitimate org asks for PIN
                'dangerous_with': ['any_context'],
            },
            'otp': {
                'points': 35,
                'safe_with': [],  # NEVER safe in incoming calls
                'dangerous_with': ['any_context'],
            },
            'password': {
                'points': 35,
                'safe_with': [],  # NEVER safe
                'dangerous_with': ['any_context'],
            },
            'police': {
                'points': 20,
                'safe_with': ['reported_crime_followup'],
                'dangerous_with': ['unsolicited_incoming', 'with_fee_request', 'with_threat'],
            },
            'bank': {
                'points': 10,
                'safe_with': ['outbound_call_to_bank', 'known_caller'],
                'dangerous_with': ['unsolicited_incoming', 'with_pin_request'],
            },
            'loan': {
                'points': 12,
                'safe_with': ['outbound_call_to_bank', 'known_caller'],
                'dangerous_with': ['unsolicited_incoming', 'with_fee_request'],
            },
            'winner': {
                'points': 22,
                'safe_with': ['known_promotion'],
                'dangerous_with': ['unsolicited_incoming', 'with_fee_request'],
            },
            'prize': {
                'points': 22,
                'safe_with': ['known_promotion'],
                'dangerous_with': ['unsolicited_incoming', 'with_fee_request'],
            },
            'free': {
                'points': 10,
                'safe_with': ['known_promotion', 'marketing_call'],
                'dangerous_with': ['unsolicited_incoming', 'with_fee_request'],
            },
            'offer': {
                'points': 10,
                'safe_with': ['known_promotion', 'marketing_call'],
                'dangerous_with': ['unsolicited_incoming', 'with_fee_request', 'with_urgency'],
            },
            'limited': {
                'points': 10,
                'safe_with': ['known_promotion', 'marketing_call'],
                'dangerous_with': ['unsolicited_incoming', 'with_urgency', 'with_fee_request'],
            },
            'government': {
                'points': 15,
                'safe_with': ['known_govt_agency'],
                'dangerous_with': ['unsolicited_incoming', 'with_fee_request', 'with_threat'],
            },
        }
        
        # ============ SAFE CALL CONTEXTS ============
        self.safe_context_patterns = {
            'outbound_call_to_bank': [
                r'(?:i|we)\s+(?:am|are)\s+calling\s+(?:from|on\s+behalf\s+of)\s+(?:kcb|equity|coop|absa|stanbic|ncba)',
                r'(?:this\s+is|my\s+name\s+is)\s+\w+\s+(?:from|with)\s+(?:kcb|equity|coop|absa)',
                r'(?:your|the)\s+(?:bank|account|loan|card)\s+(?:at|with)\s+(?:kcb|equity|coop|absa)',
            ],
            'transaction_verification': [
                r'(?:transaction|payment|transfer)\s+(?:of|for)\s+(?:ksh|kes)\s*\d+',
                r'(?:did\s+you|have\s+you)\s+(?:make|made|authorize|authorized)\s+(?:a|this)\s+(?:transaction|payment|transfer)',
                r'confirm(?:ing|ation)?\s+(?:your|the)\s+(?:transaction|payment|transfer)',
            ],
            'known_caller': [
                r'(?:as\s+per|following\s+up\s+on)\s+(?:our|your|the)\s+(?:conversation|meeting|email|request|application)',
                r'(?:you|we)\s+(?:called|emailed|contacted|reached\s+out)\s+(?:me|you|us)\s+(?:earlier|yesterday|last\s+week)',
                r'(?:returning|following\s+up)\s+(?:your|my)\s+call',
            ],
            'service_call': [
                r'(?:this\s+is|we\s+are)\s+(?:a\s+)?(?:follow-up|reminder|courtesy)\s+call',
                r'(?:your|the)\s+(?:appointment|booking|reservation|order|delivery)',
                r'(?:just|wanted\s+to)\s+(?:let\s+you\s+know|inform\s+you|remind\s+you|check)',
            ],
            'reported_crime_followup': [
                r'(?:you|someone)\s+(?:reported|filed)\s+(?:a|the)\s+(?:case|incident|crime|report)',
                r'(?:following\s+up|investigating)\s+(?:on|the)\s+(?:case|report|incident)',
                r'(?:officer|detective|inspector)\s+\w+\s+(?:here|speaking|calling)',
            ],
        }
        
        # ============ SCAM NUMBER PATTERNS ============
        self.scam_number_patterns = {
            'premium_rate': {
                'patterns': [r'^0900', r'^0906', r'^0907', r'^0908', r'^0909', r'^0905', r'^0904'],
                'risk': 85,
                'message': '⚠️ Premium rate number - calls may cost Ksh 100+ per minute'
            },
            'international_scam': {
                'patterns': [r'^\+88[0-9]', r'^\+92[0-9]', r'^\+23[0-9]', r'^\+1[0-9]{10}'],
                'risk': 75,
                'message': '⚠️ International number - common scam origin'
            },
            'spoofed_likely': {
                'patterns': [r'^07[0-9]{7}$', r'^01[0-9]{8}$'],
                'risk': 15,
                'message': 'Regular mobile number - verify before trusting'
            },
            'toll_free_scam': {
                'patterns': [r'^0800', r'^0801', r'^0802'],
                'risk': 30,
                'message': '⚠️ Toll-free number - scammers sometimes use these'
            },
            'repeated_digits': {
                'patterns': [r'(\d)\1{5,}'],
                'risk': 25,
                'message': '⚠️ Suspicious repeated digits - often used by spammers'
            }
        }
        
        # ============ SCAM PHRASES ============
        self.scam_phrases = {
            'critical': [
                (r'send money (to|via|using)', 'Urgent money transfer request', 30),
                (r'transfer.*money.*(now|immediately|urgent)', 'Urgent money transfer', 30),
                (r'(mpin|m-pin|mpesa pin|m-pesa pin)', 'M-Pesa PIN request', 35),
                (r'(otp|one time password|verification code)', 'OTP/Verification code request', 35),
                (r'(password|passcode|security code)', 'Password request', 35),
                (r'bank details|credit card|debit card', 'Bank/Credit card details request', 30),
                (r'account (suspended|blocked|closed|terminated)', 'Account suspension threat', 25),
                (r'(legal action|law suit|court case|attorney|lawyer)', 'Legal action threat', 25),
                (r'(police|arrest|warrant|criminal case)', 'Police involvement threat', 25),
                (r'(jail|prison|detention|arrested)', 'Jail/Arrest threat', 25),
                (r'(immediate action|act now|right now)', 'Urgency pressure tactic', 20),
                (r'(limited time|expires today|last chance)', 'Limited time pressure', 20),
                (r'(within (24|48|12) hours|today only)', 'Time pressure', 20),
            ],
            'high_risk': [
                (r'send money', 'Money transfer request', 20),
                (r'transfer.*money', 'Money transfer request', 20),
                (r'mpesa pin', 'M-Pesa PIN request', 25),
                (r'pin number', 'PIN request', 25),
                (r'otp', 'OTP/Verification code request', 25),
                (r'verification code', 'Verification code request', 25),
                (r'password', 'Password request', 25),
                (r'account suspended', 'Account suspension threat', 20),
                (r'account blocked', 'Account blocked threat', 20),
                (r'account will be closed', 'Account closure threat', 20),
                (r'legal action', 'Legal action threat', 18),
                (r'police', 'Police involvement threat', 18),
                (r'immediate action required', 'Urgency tactic', 18),
                (r'you have been selected', 'Selection scam', 15),
                (r'urgent response needed', 'Urgency tactic', 15),
            ],
            'medium_risk': [
                (r'urgent', 'Urgency language', 12),
                (r'as soon as possible', 'Pressure language', 10),
                (r'limited time', 'Limited time pressure', 10),
                (r'verify your account', 'Verification request', 12),
                (r'confirm your identity', 'Identity confirmation', 12),
                (r'update your details', 'Details update request', 10),
                (r'processing fee', 'Fee request', 15),
                (r'registration fee', 'Fee request', 15),
                (r'activation fee', 'Fee request', 15),
                (r'congratulations', 'Prize/Lottery scam', 12),
                (r'you won', 'Prize scam', 12),
                (r'cash reward', 'Reward scam', 12),
                (r'free gift', 'Free gift scam', 10),
                (r'important notice', 'Important notice scam', 10),
                (r'security alert', 'Security alert scam', 12),
            ],
            'impersonation': [
                (r'safaricom', 'Safaricom impersonation', 20),
                (r'mpesa', 'M-Pesa impersonation', 20),
                (r'airtel', 'Airtel impersonation', 20),
                (r'telkom', 'Telkom impersonation', 20),
                (r'equity', 'Equity Bank impersonation', 20),
                (r'kcb', 'KCB Bank impersonation', 20),
                (r'cooperative|co-op', 'Co-op Bank impersonation', 20),
                (r'absa|barclays', 'Absa Bank impersonation', 20),
                (r'bank', 'Bank impersonation', 15),
                (r'police', 'Police impersonation', 25),
                (r'government', 'Government impersonation', 20),
                (r'kra', 'KRA impersonation', 20),
                (r'ntsa', 'NTSA impersonation', 18),
                (r'ecitizen', 'eCitizen impersonation', 18),
                (r'crb|credit reference', 'CRB impersonation', 20),
            ],
            'swahili': [
                (r'tuma pesa', 'Send money request (Swahili)', 20),
                (r'namba ya siri', 'Secret number/PIN request', 25),
                (r'siri yako', 'Your secret/PIN', 25),
                (r'fungua akaunti', 'Open account', 15),
                (r'kufungiwa', 'Blocked/Suspended', 20),
                (r'hatari', 'Danger/Urgent', 15),
                (r'haraka sana', 'Very urgent', 15),
                (r'sasa hivi', 'Right now', 12),
                (r'lipa', 'Pay', 15),
                (r'pesa', 'Money', 10),
                (r'nambari ya siri', 'Secret number', 25),
                (r'akaunti yako', 'Your account', 12),
            ],
        }
        
        # ============ ML-INSPIRED WEIGHTING ============
        self.weights = {
            'critical_multiplier': 1.5,
            'repetition_penalty': 0.3,
            'legitimate_correction': 0.4,
        }
        
        # ============ REPORTED SCAMS STORAGE ============
        self.reported_scam_numbers = self._load_reported_scams()
        self.pattern_memory = self._load_pattern_memory()
    
    def _load_reported_scams(self) -> set:
        reported = set()
        try:
            data_dir = os.path.join(os.path.dirname(__file__), 'data')
            os.makedirs(data_dir, exist_ok=True)
            scam_file = os.path.join(data_dir, 'reported_scams.json')
            if os.path.exists(scam_file):
                with open(scam_file, 'r') as f:
                    reported = set(json.load(f).get('numbers', []))
        except Exception:
            pass
        return reported
    
    def _load_pattern_memory(self) -> dict:
        memory = {}
        try:
            data_dir = os.path.join(os.path.dirname(__file__), 'data')
            memory_file = os.path.join(data_dir, 'pattern_memory.json')
            if os.path.exists(memory_file):
                with open(memory_file, 'r') as f:
                    memory = json.load(f)
        except Exception:
            pass
        return memory
    
    def _save_reported_scams(self):
        try:
            data_dir = os.path.join(os.path.dirname(__file__), 'data')
            os.makedirs(data_dir, exist_ok=True)
            with open(os.path.join(data_dir, 'reported_scams.json'), 'w') as f:
                json.dump({'numbers': list(self.reported_scam_numbers), 'last_updated': datetime.now().isoformat()}, f)
        except Exception:
            pass
    
    def _save_pattern_memory(self):
        try:
            data_dir = os.path.join(os.path.dirname(__file__), 'data')
            os.makedirs(data_dir, exist_ok=True)
            with open(os.path.join(data_dir, 'pattern_memory.json'), 'w') as f:
                json.dump(self.pattern_memory, f)
        except Exception:
            pass
    
    def _analyze_call_context(self, transcript: str) -> Dict:
        """Analyze the context of a call transcript."""
        text_lower = transcript.lower()
        
        context = {
            'is_outbound_to_bank': False,
            'is_transaction_verification': False,
            'is_known_caller': False,
            'is_service_call': False,
            'is_crime_followup': False,
            'has_pin_request': False,
            'has_urgency': False,
            'has_fee_request': False,
            'has_threat': False,
            'has_unknown_caller': False,
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
        
        # Check danger signals
        if re.search(r'(?:send|share|provide|enter|type|give|tuma)\s+(?:your\s+)?(?:pin|otp|mpin|password|secret|siri)', text_lower):
            context['has_pin_request'] = True
            context['danger_signal_count'] += 10
        
        if re.search(r'urgent|immediately|asap|haraka|right\s+now|sasa\s+hivi', text_lower):
            context['has_urgency'] = True
            context['danger_signal_count'] += 4
        
        if re.search(r'pay\s+(?:ksh|kes)\s*\d+|send\s+(?:ksh|kes)\s*\d+|processing\s+fee|registration\s+fee|lipa\s+ksh', text_lower):
            context['has_fee_request'] = True
            context['danger_signal_count'] += 5
        
        if re.search(r'suspended|blocked|locked|deactivated|closed|terminated|legal\s+action|arrest|jail|prison', text_lower):
            context['has_threat'] = True
            context['danger_signal_count'] += 4
        
        # Unknown caller detection
        if not context['is_known_caller'] and not context['is_outbound_to_bank']:
            if re.search(r'(?:this\s+is|my\s+name\s+is|i\s+am\s+calling)', text_lower):
                context['has_unknown_caller'] = False  # They identified themselves
            else:
                context['has_unknown_caller'] = True
                context['danger_signal_count'] += 2
        
        return context
    
    def _is_word_safe_in_context(self, word: str, context: Dict) -> bool:
        """Determine if a word is safe based on call context."""
        if word not in self.context_dependent_words:
            return False
        
        word_info = self.context_dependent_words[word]
        safe_contexts = word_info.get('safe_with', [])
        
        for safe_ctx in safe_contexts:
            if safe_ctx == 'outbound_call_to_bank' and context['is_outbound_to_bank']:
                return True
            if safe_ctx == 'outbound_call_to_telco' and context['is_service_call']:
                return True
            if safe_ctx == 'known_caller' and context['is_known_caller']:
                return True
            if safe_ctx == 'transaction_verification' and context['is_transaction_verification']:
                return True
            if safe_ctx == 'service_call' and context['is_service_call']:
                return True
            if safe_ctx == 'reported_crime_followup' and context['is_crime_followup']:
                return True
            if safe_ctx == 'known_promotion' and context['safe_context_count'] >= 1:
                return True
            if safe_ctx == 'marketing_call' and context['safe_context_count'] >= 1:
                return True
        
        return False
    
    def analyze_phone_number(self, phone_number: str) -> Dict:
        """Enhanced phone number analysis with database integration."""
        cleaned = re.sub(r'\D', '', str(phone_number))
        score = 0
        warnings = []
        risk_factors = []
        category = 'unknown'
        
        # Check legitimate numbers
        if cleaned in self.legitimate_numbers:
            return {
                'score': 0, 'risk_level': 'SAFE', 'color': 'success',
                'emoji': '✅', 'message': f"✓ Legitimate: {self.legitimate_numbers[cleaned]}",
                'warnings': [], 'risk_factors': ['Verified legitimate number'],
                'category': 'legitimate', 'type': 'PHONE_NUMBER'
            }
        
        # Check BlockedNumber database (primary source)
        try:
            from detector.models import BlockedNumber
            blocked = BlockedNumber.objects.filter(phone_number=cleaned).first()
            if blocked and blocked.status in ('CONFIRMED', 'BLOCKED'):
                score += 60
                warnings.append(f"🔴 This number has been reported {blocked.report_count} times as a scam!")
                risk_factors.append('Confirmed scam in database')
                category = 'confirmed_scam'
            elif blocked and blocked.status == 'PENDING':
                score += 30
                warnings.append(f"⚠️ This number has {blocked.report_count} pending scam reports")
                risk_factors.append('Under investigation')
                category = 'suspected_scam'
        except Exception:
            pass
        
        # Fallback to local storage
        if cleaned in self.reported_scam_numbers:
            score += 40
            warnings.append("🔴 This number has been reported as a scam caller")
            risk_factors.append('Previously reported')
            category = category or 'reported_scam'
        
        # Pattern analysis
        for category_name, info in self.scam_number_patterns.items():
            for pattern in info['patterns']:
                if re.match(pattern, cleaned):
                    score += info['risk']
                    warnings.append(f"⚠️ {info['message']}")
                    risk_factors.append(category_name.replace('_', ' ').title())
                    category = category or category_name
                    break
        
        score = min(100, score)
        
        if score >= 70:
            risk_level, color, emoji = 'CRITICAL RISK', 'danger', '🔴'
            message = '🔴 CRITICAL: This number is highly likely a scammer! BLOCK and REPORT immediately.'
        elif score >= 50:
            risk_level, color, emoji = 'HIGH RISK', 'danger', '🔴'
            message = '⚠️ HIGH RISK: This number has strong scam indicators.'
        elif score >= 25:
            risk_level, color, emoji = 'MEDIUM RISK', 'warning', '🟡'
            message = '⚠️ MEDIUM RISK: This number has suspicious characteristics.'
        else:
            risk_level, color, emoji = 'LOW RISK', 'success', '🟢'
            message = '✓ LOW RISK: This number appears legitimate.'
        
        return {
            'score': score, 'risk_level': risk_level, 'color': color,
            'emoji': emoji, 'message': message, 'warnings': warnings[:5],
            'risk_factors': risk_factors[:5], 'category': category,
            'cleaned_number': cleaned, 'type': 'PHONE_NUMBER'
        }
    
    def analyze_call_transcript(self, transcript: str, caller_number: str = None) -> Dict:
        """Context-aware call transcript analysis."""
        
        if not transcript or not transcript.strip():
            return {
                'score': 0, 'risk_level': 'LOW RISK', 'color': 'success',
                'emoji': '🟢', 'message': 'No transcript provided',
                'warnings': ['Please provide call transcript for analysis'],
                'recommendations': ['Paste what the caller said during the conversation'],
                'detected_categories': [], 'impersonations': [],
                'transcript_length': 0, 'confidence': 0,
                'type': 'CALL', 'phrase_matches': [], 'context': {}
            }
        
        text_lower = transcript.lower()
        score = 0
        warnings = []
        detected_categories = []
        detected_impersonations = []
        phrase_matches = []
        context_adjustments = []
        
        # ============ CONTEXT ANALYSIS ============
        context = self._analyze_call_context(transcript)
        
        # Safe context with no danger signals = likely legitimate
        if context['safe_context_count'] >= 2 and context['danger_signal_count'] == 0:
            score -= 25
            context_adjustments.append("✅ Safe call context detected - score reduced")
        
        # ============ CRITICAL PATTERNS ============
        for pattern, description, points in self.scam_phrases['critical']:
            if re.search(pattern, text_lower):
                # Check if critical word is context-dependent
                for word in self.context_dependent_words:
                    if word in text_lower and self._is_word_safe_in_context(word, context):
                        context_adjustments.append(f"✅ '{word}' is safe in this call context")
                        continue
                
                points *= self.weights['critical_multiplier']
                score += points
                warnings.append(f"🔴🔴 {description}")
                detected_categories.append('critical')
                phrase_matches.append({'pattern': pattern, 'description': description, 'severity': 'critical'})
                break
        
        # ============ HIGH RISK PATTERNS ============
        for pattern, description, points in self.scam_phrases['high_risk']:
            if re.search(pattern, text_lower):
                should_skip = False
                for word in self.context_dependent_words:
                    if word in text_lower and self._is_word_safe_in_context(word, context):
                        should_skip = True
                        context_adjustments.append(f"✅ '{word}' is safe in this call context")
                        break
                
                if not should_skip and description not in [w.replace('🔴 ', '') for w in warnings if w.startswith('🔴')]:
                    score += points
                    warnings.append(f"🔴 {description}")
                    detected_categories.append('high_risk')
                    phrase_matches.append({'pattern': pattern, 'description': description, 'severity': 'high'})
        
        # ============ MEDIUM RISK PATTERNS ============
        for pattern, description, points in self.scam_phrases['medium_risk']:
            if re.search(pattern, text_lower):
                should_skip = False
                for word in self.context_dependent_words:
                    if word in text_lower and self._is_word_safe_in_context(word, context):
                        should_skip = True
                        break
                
                if not should_skip and description not in [w.replace('🟡 ', '') for w in warnings if w.startswith('🟡')]:
                    score += points
                    warnings.append(f"🟡 {description}")
                    detected_categories.append('medium_risk')
                    phrase_matches.append({'pattern': pattern, 'description': description, 'severity': 'medium'})
        
        # ============ IMPERSONATION ============
        for pattern, description, points in self.scam_phrases['impersonation']:
            if re.search(pattern, text_lower):
                # Don't flag impersonation if caller is actually from that org
                if context['is_outbound_to_bank'] and any(b in description.lower() for b in ['bank', 'kcb', 'equity', 'coop', 'absa']):
                    context_adjustments.append(f"✅ '{description}' appears legitimate in this context")
                    continue
                if context['is_service_call'] and any(t in description.lower() for t in ['safaricom', 'airtel', 'telkom']):
                    context_adjustments.append(f"✅ '{description}' appears legitimate in this context")
                    continue
                
                score += points
                warnings.append(f"🎭 {description}")
                detected_impersonations.append(description)
                detected_categories.append('impersonation')
        
        # ============ SWAHILI ============
        for pattern, description, points in self.scam_phrases['swahili']:
            if re.search(pattern, text_lower):
                score += points
                warnings.append(f"🇰🇪 {description}")
                detected_categories.append('swahili')
                break
        
        # ============ CONTEXTUAL CHECKS ============
        urgency_count = sum(1 for w in ['urgent', 'immediately', 'asap', 'now', 'today'] if w in text_lower)
        if urgency_count >= 2:
            score += 12
            warnings.append("⏰ Multiple urgency words detected - classic pressure tactic")
        
        if re.search(r'can\'t tell|not allowed to say|confidential|secret', text_lower):
            score += 15
            warnings.append("🤫 Caller refusing to identify themselves - major red flag")
        
        if re.search(r'don\'t hang up|stay on the line|don\'t disconnect', text_lower):
            score += 12
            warnings.append("📞 Caller trying to isolate you - common scam tactic")
        
        if re.search(r'don\'t tell anyone|keep this confidential|between us', text_lower):
            score += 15
            warnings.append("🤐 Caller asking for secrecy - major scam indicator")
        
        # ============ CONTEXT-AWARE ADJUSTMENTS ============
        if context['is_outbound_to_bank'] and not context['has_pin_request']:
            score = max(0, score - 20)
            context_adjustments.append("✅ Bank call context detected")
        
        if context['is_known_caller'] and context['danger_signal_count'] < 3:
            score = max(0, score - 15)
            context_adjustments.append("✅ Known caller context detected")
        
        if context['has_pin_request']:
            score = min(100, score + 30)
            warnings.append("🔴 CRITICAL: Caller requested PIN/OTP/password - this is NEVER legitimate!")
        
        if context['has_urgency'] and context['has_fee_request']:
            score = min(100, score + 20)
            warnings.append("🔴 Urgency + Money request = Classic scam pattern")
        
        # ============ LEGITIMATE INDICATORS ============
        for indicator in [r'thank you for calling', r'customer service', r'how may I help you',
                          r'your call is important', r'please hold', r'we value your business']:
            if re.search(indicator, text_lower):
                score = max(0, score - 10)
        
        # ============ FINAL SCORE ============
        confidence = min(100, (score / 100) * 100) if score > 0 else 0
        score = min(100, round(score, 1))
        
        # ============ RECOMMENDATIONS ============
        recommendations = []
        if 'critical' in detected_categories or context['has_pin_request']:
            recommendations.append("🚨🚨 CRITICAL: HANG UP IMMEDIATELY!")
            recommendations.append("🔐 NEVER share PIN, password, or OTP with anyone!")
        elif score >= 60:
            recommendations.append("🚨 BLOCK this number immediately")
            recommendations.append("❌ DO NOT send money or share information")
        elif score >= 30:
            recommendations.append("⚠️ Verify caller through official channels")
            recommendations.append("📞 Hang up and call back on official number")
        else:
            recommendations.append("✅ Always verify unexpected calls")
        
        if detected_impersonations:
            recommendations.append("🏢 Caller is impersonating an organization")
            recommendations.append("📱 Find official number on their website and call back")
        
        recommendations.append("📞 Report scam calls to 333 (Safaricom) or 3333 (Airtel)")
        recommendations = list(dict.fromkeys(recommendations))[:6]
        
        # ============ RISK LEVEL ============
        if score >= 70:
            risk_level, color, emoji = "CRITICAL - SCAM CALL CONFIRMED", "danger", "🔴🚨🚨"
            message = "⚠️⚠️ CRITICAL: This call shows overwhelming scam indicators! HANG UP NOW!"
        elif score >= 50:
            risk_level, color, emoji = "HIGH RISK - SCAM CALL DETECTED", "danger", "🔴🚨"
            message = "⚠️ This call shows strong scam indicators! HANG UP immediately."
        elif score >= 25:
            risk_level, color, emoji = "MEDIUM RISK - SUSPICIOUS", "warning", "🟡⚠️"
            message = "⚠️ This call has suspicious elements. Verify through official channels."
        else:
            risk_level, color, emoji = "LOW RISK - LIKELY SAFE", "success", "🟢✅"
            message = "✓ No scam patterns detected, but always exercise caution."
        
        return {
            'score': score, 'risk_level': risk_level, 'color': color,
            'emoji': emoji, 'message': message,
            'warnings': warnings[:12], 'recommendations': recommendations[:6],
            'detected_categories': list(set(detected_categories)),
            'impersonations': detected_impersonations[:3],
            'transcript_length': len(transcript), 'confidence': confidence,
            'type': 'CALL', 'phrase_matches': phrase_matches[:5],
            'context': {
                'safe_contexts': context['safe_context_count'],
                'danger_signals': context['danger_signal_count'],
                'is_outbound_to_bank': context['is_outbound_to_bank'],
                'is_known_caller': context['is_known_caller'],
                'context_adjustments': context_adjustments[:3],
            }
        }
    
    def report_scam_number(self, phone_number: str, description: str = '') -> Dict:
        cleaned = re.sub(r'\D', '', str(phone_number))
        
        # Also save to BlockedNumber database
        try:
            from detector.models import BlockedNumber
            obj, created = BlockedNumber.objects.get_or_create(
                phone_number=cleaned,
                defaults={'report_count': 1, 'scam_category': 'Phone Call Scam',
                          'description': description, 'reported_by': 'phone_detector'}
            )
            if not created:
                obj.report_count += 1
                obj.calculate_confidence()
                obj.save()
        except Exception:
            pass
        
        # Local storage fallback
        if cleaned not in self.reported_scam_numbers:
            self.reported_scam_numbers.add(cleaned)
            if cleaned not in self.pattern_memory:
                self.pattern_memory[cleaned] = {'reports': 0, 'first_seen': datetime.now().isoformat()}
            self.pattern_memory[cleaned]['reports'] = self.pattern_memory[cleaned].get('reports', 0) + 1
            self.pattern_memory[cleaned]['last_reported'] = datetime.now().isoformat()
            if description:
                self.pattern_memory[cleaned]['description'] = description[:200]
            self._save_reported_scams()
            self._save_pattern_memory()
            
            return {'status': 'success', 'message': f'Number {cleaned} reported!', 'number': cleaned}
        
        return {'status': 'info', 'message': f'Number {cleaned} already reported.', 'number': cleaned}
    
    def get_scam_statistics(self) -> Dict:
        return {
            'total_reported_numbers': len(self.reported_scam_numbers),
            'most_reported': sorted(self.pattern_memory.items(), key=lambda x: x[1].get('reports', 0), reverse=True)[:10],
            'last_updated': datetime.now().isoformat()
        }


# Singleton instance
phone_detector = PhoneScamDetector()


def detect_call_scam(transcript: str, phone_number: str = None) -> Dict:
    result = phone_detector.analyze_call_transcript(transcript)
    if phone_number:
        number_analysis = phone_detector.analyze_phone_number(phone_number)
        result['number_analysis'] = number_analysis
        combined_score = (result['score'] * 0.7) + (number_analysis['score'] * 0.3)
        result['combined_score'] = round(combined_score, 1)
        result['score'] = round(combined_score, 1)
        if combined_score >= 70:
            result['risk_level'] = "CRITICAL - SCAM CALL CONFIRMED"
            result['color'] = "danger"
            result['emoji'] = "🔴🚨🚨"
            result['message'] = "⚠️⚠️ CRITICAL: Both number and conversation indicate a scam! HANG UP NOW!"
        elif combined_score >= 50:
            result['risk_level'] = "HIGH RISK - SCAM CALL DETECTED"
            result['color'] = "danger"
            result['emoji'] = "🔴🚨"
            result['message'] = "⚠️ This call shows strong scam indicators! HANG UP immediately!"
    return result


def check_phone_number(phone_number: str) -> Dict:
    return phone_detector.analyze_phone_number(phone_number)


def report_scam_call_number(phone_number: str, description: str = '') -> Dict:
    return phone_detector.report_scam_number(phone_number, description)


def get_scam_statistics() -> Dict:
    return phone_detector.get_scam_statistics()