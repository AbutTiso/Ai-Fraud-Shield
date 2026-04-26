# detector/phone_detector.py
import re
from datetime import datetime
import json
import os
from typing import Dict, List, Tuple, Optional

class PhoneScamDetector:
    """Advanced Phone Call Scam Detection - Enhanced Accuracy"""
    
    def __init__(self):
        # ============ ENHANCED LEGITIMATE NUMBERS DATABASE ============
        self.legitimate_numbers = {
            # Safaricom Official Numbers
            '0722000000': 'Safaricom Official',
            '0722000001': 'Safaricom Official',
            '0722000002': 'Safaricom Official',
            '0722000003': 'Safaricom Official',
            '0722000004': 'Safaricom Official',
            '0722000005': 'Safaricom Official',
            '0722000006': 'Safaricom Official',
            '0722000007': 'Safaricom Official',
            '0722000008': 'Safaricom Official',
            '0722000009': 'Safaricom Official',
            # Customer Care Numbers
            '100': 'Safaricom Customer Care',
            '200': 'Safaricom Customer Care',
            '333': 'Safaricom Scam Reporting',
            '3333': 'Airtel Scam Reporting',
            '150': 'Airtel Customer Care',
            '151': 'Airtel Customer Care',
            '123': 'Telkom Customer Care',
            '124': 'Telkom Customer Care',
            # Bank Official Numbers
            '0703070000': 'Equity Bank Official',
            '0711047000': 'KCB Official',
            '0711025000': 'Co-op Bank Official',
            '0703023000': 'Absa Bank Official',
            # Emergency Services
            '112': 'Emergency Services',
            '911': 'Emergency Services',
            '999': 'Police Emergency',
        }
        
        # ============ ENHANCED SCAM NUMBER PATTERNS ============
        self.scam_number_patterns = {
            'premium_rate': {
                'patterns': [r'^0900', r'^0906', r'^0907', r'^0908', r'^0909', r'^0905', r'^0904'],
                'risk': 85,
                'message': '⚠️ Premium rate number - calls may cost Ksh 100+ per minute'
            },
            'international_scam': {
                'patterns': [r'^\+88[0-9]', r'^\+92[0-9]', r'^\+23[0-9]', r'^\+1[0-9]{10}'],
                'risk': 75,
                'message': '⚠️ International number - common scam origin (India/Pakistan/Nigeria)'
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
        
        # ============ ENHANCED SCAM PHRASES WITH WEIGHTED SCORING ============
        self.scam_phrases = {
            'critical': [
                # Money-related (highest weight)
                (r'send money (to|via|using)', 'Urgent money transfer request', 30),
                (r'transfer.*money.*(now|immediately|urgent)', 'Urgent money transfer', 30),
                (r'(mpin|m-pin|mpesa pin|m-pesa pin)', 'M-Pesa PIN request', 35),
                (r'(otp|one time password|verification code)', 'OTP/Verification code request', 35),
                (r'(password|passcode|security code)', 'Password request', 35),
                (r'bank details|credit card|debit card', 'Bank/Credit card details request', 30),
                
                # Threat-based
                (r'account (suspended|blocked|closed|terminated)', 'Account suspension threat', 25),
                (r'(legal action|law suit|court case|attorney|lawyer)', 'Legal action threat', 25),
                (r'(police|arrest|warrant|criminal case)', 'Police involvement threat', 25),
                (r'(jail|prison|detention|arrested)', 'Jail/Arrest threat', 25),
                
                # Urgency/pressure
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
        
        # ============ ML-INSPIRED WEIGHTING FACTORS ============
        self.weights = {
            'critical_multiplier': 1.5,
            'repetition_penalty': 0.3,  # Reduce score if same scam type repeated
            'legitimate_correction': 0.4,  # Reduce score if legitimate indicators found
        }
        
        # ============ KNOWN SCAM NUMBERS DATABASE (REPORTED) ============
        self.reported_scam_numbers = self._load_reported_scams()
        
        # ============ PATTERN MEMORY (for detecting repeat offenders) ============
        self.pattern_memory = {}
        
    def _load_reported_scams(self) -> set:
        """Load reported scam numbers from file (if exists)"""
        reported = set()
        try:
            scam_file = os.path.join(os.path.dirname(__file__), 'data', 'reported_scams.json')
            if os.path.exists(scam_file):
                with open(scam_file, 'r') as f:
                    data = json.load(f)
                    reported = set(data.get('numbers', []))
        except Exception:
            pass
        return reported
    
    def _save_reported_scams(self):
        """Save reported scam numbers to file"""
        try:
            os.makedirs(os.path.dirname(__file__) + '/data', exist_ok=True)
            scam_file = os.path.join(os.path.dirname(__file__), 'data', 'reported_scams.json')
            with open(scam_file, 'w') as f:
                json.dump({'numbers': list(self.reported_scam_numbers), 'last_updated': datetime.now().isoformat()}, f)
        except Exception:
            pass
    
    def analyze_phone_number(self, phone_number: str) -> Dict:
        """Enhanced phone number analysis with multiple factors"""
        cleaned = re.sub(r'\D', '', str(phone_number))
        score = 0
        warnings = []
        risk_factors = []
        category = 'unknown'
        
        # Check legitimate numbers
        if cleaned in self.legitimate_numbers:
            return {
                'score': 0,
                'risk_level': 'SAFE',
                'color': 'success',
                'emoji': '✅',
                'message': f"✓ Legitimate: {self.legitimate_numbers[cleaned]}",
                'warnings': [],
                'risk_factors': ['Verified legitimate number'],
                'category': 'legitimate'
            }
        
        # Check reported scam numbers
        if cleaned in self.reported_scam_numbers:
            score += 60
            warnings.append("🔴 This number has been reported as a scam caller by multiple users")
            risk_factors.append('Previously reported as scam')
            category = 'reported_scam'
        
        # Check pattern history
        if cleaned in self.pattern_memory:
            repeat_count = self.pattern_memory[cleaned].get('reports', 0)
            if repeat_count > 0:
                score += min(30, repeat_count * 5)
                warnings.append(f"⚠️ This number has been flagged {repeat_count} times before")
        
        # Analyze against patterns
        for category_name, info in self.scam_number_patterns.items():
            for pattern in info['patterns']:
                if re.match(pattern, cleaned):
                    score += info['risk']
                    warnings.append(f"⚠️ {info['message']}")
                    risk_factors.append(category_name.replace('_', ' ').title())
                    category = category_name
                    break
        
        # Check for suspicious length
        if len(cleaned) == 12 and cleaned.startswith('254'):
            score += 5
            risk_factors.append('International format - possible spoof')
        
        # Check for number spoofing indicators
        if len(cleaned) == 10 and cleaned.startswith('0'):
            if cleaned[1:3] in ['71', '72', '73', '74', '75', '76', '77', '78', '79']:
                # This is a valid Kenyan mobile prefix, but could still be spoofed
                pass
        
        score = min(100, score)
        
        # Determine risk level
        if score >= 70:
            risk_level = 'CRITICAL RISK'
            color = 'danger'
            emoji = '🔴'
            message = '🔴 CRITICAL: This number is highly likely a scammer! BLOCK and REPORT immediately.'
        elif score >= 50:
            risk_level = 'HIGH RISK'
            color = 'danger'
            emoji = '🔴'
            message = '⚠️ HIGH RISK: This number has strong scam indicators. Be very careful!'
        elif score >= 25:
            risk_level = 'MEDIUM RISK'
            color = 'warning'
            emoji = '🟡'
            message = '⚠️ MEDIUM RISK: This number has suspicious characteristics. Verify carefully.'
        else:
            risk_level = 'LOW RISK'
            color = 'success'
            emoji = '🟢'
            message = '✓ LOW RISK: This number appears legitimate, but always verify.'
        
        return {
            'score': score,
            'risk_level': risk_level,
            'color': color,
            'emoji': emoji,
            'message': message,
            'warnings': warnings[:5],
            'risk_factors': risk_factors[:5],
            'category': category,
            'cleaned_number': cleaned
        }
    
    def analyze_call_transcript(self, transcript: str, caller_number: str = None) -> Dict:
        """Enhanced call transcript analysis with weighted scoring and context awareness"""
        
        if not transcript or not transcript.strip():
            return {
                'score': 0,
                'risk_level': 'LOW RISK',
                'color': 'success',
                'emoji': '🟢',
                'message': 'No transcript provided',
                'warnings': ['Please provide call transcript for analysis'],
                'recommendations': ['Paste what the caller said during the conversation'],
                'detected_categories': [],
                'confidence': 0
            }
        
        text_lower = transcript.lower()
        score = 0
        warnings = []
        detected_categories = []
        detected_impersonations = []
        phrase_matches = []
        
        # ============ CRITICAL PATTERN DETECTION (Highest Priority) ============
        for pattern, description, points in self.scam_phrases['critical']:
            matches = re.findall(pattern, text_lower)
            if matches:
                points *= self.weights['critical_multiplier']
                score += points
                warnings.append(f"🔴🔴 {description}")
                detected_categories.append('critical')
                phrase_matches.append({'pattern': pattern, 'description': description, 'severity': 'critical'})
                break  # Only add one critical match to avoid overwhelming
        
        # ============ HIGH RISK PATTERNS ============
        for pattern, description, points in self.scam_phrases['high_risk']:
            if re.search(pattern, text_lower):
                # Check if this is a duplicate category
                if description not in [w.replace('🔴 ', '') for w in warnings]:
                    score += points
                    warnings.append(f"🔴 {description}")
                    detected_categories.append('high_risk')
                    phrase_matches.append({'pattern': pattern, 'description': description, 'severity': 'high'})
                break
        
        # ============ MEDIUM RISK PATTERNS ============
        for pattern, description, points in self.scam_phrases['medium_risk']:
            if re.search(pattern, text_lower):
                if description not in [w.replace('🟡 ', '') for w in warnings]:
                    score += points
                    warnings.append(f"🟡 {description}")
                    detected_categories.append('medium_risk')
                    phrase_matches.append({'pattern': pattern, 'description': description, 'severity': 'medium'})
                break
        
        # ============ IMPERSONATION DETECTION ============
        for pattern, description, points in self.scam_phrases['impersonation']:
            if re.search(pattern, text_lower):
                score += points
                warnings.append(f"🎭 {description}")
                detected_impersonations.append(description)
                detected_categories.append('impersonation')
                phrase_matches.append({'pattern': pattern, 'description': description, 'severity': 'impersonation'})
        
        # ============ SWAHILI PHRASE DETECTION ============
        for pattern, description, points in self.scam_phrases['swahili']:
            if re.search(pattern, text_lower):
                score += points
                warnings.append(f"🇰🇪 {description}")
                detected_categories.append('swahili')
                phrase_matches.append({'pattern': pattern, 'description': description, 'severity': 'swahili'})
                break
        
        # ============ CONTEXTUAL ANALYSIS ============
        
        # Check for pressure tactics combination
        urgency_count = sum(1 for w in ['urgent', 'immediately', 'asap', 'now', 'today'] if w in text_lower)
        if urgency_count >= 2:
            score += 12
            warnings.append("⏰ Multiple urgency words detected - classic pressure tactic")
        
        # Check for refusal to identify
        if re.search(r'can\'t tell|not allowed to say|confidential|secret', text_lower):
            score += 15
            warnings.append("🤫 Caller refusing to properly identify themselves - major red flag")
        
        # Check for request to stay on line
        if re.search(r'don\'t hang up|stay on the line|don\'t disconnect|stay with me', text_lower):
            score += 12
            warnings.append("📞 Caller trying to isolate you - common scam tactic to prevent verification")
        
        # Check for sense of urgency + money combination
        if ('urgent' in text_lower or 'immediately' in text_lower) and ('send' in text_lower or 'pay' in text_lower):
            score += 10
            warnings.append("⏰💰 Urgency + Money request - scammer creating false urgency")
        
        # Check for "press 1" or automated system scams
        if re.search(r'press \d|choose an option|for english', text_lower):
            score += 8
            warnings.append("📞 Automated system prompt - often used in vishing scams")
        
        # Check for secrecy requests
        if re.search(r'don\'t tell anyone|keep this confidential|between us', text_lower):
            score += 15
            warnings.append("🤐 Caller asking for secrecy - major scam indicator")
        
        # ============ LEGITIMATE INDICATORS (Reduce Score) ============
        legitimate_indicators = [
            r'thank you for calling', r'customer service', r'how may I help you',
            r'your call is important', r'please hold', r'we value your business'
        ]
        
        for indicator in legitimate_indicators:
            if re.search(indicator, text_lower):
                score = max(0, score - 10)
                warnings.append(f"✓ Legitimate indicator detected: '{indicator[:30]}...'")
        
        # ============ CONFIDENCE SCORE ============
        confidence = min(100, (score / 100) * 100) if score > 0 else 0
        
        score = min(100, score)
        
        # ============ INTELLIGENT RECOMMENDATIONS ============
        recommendations = []
        
        if 'critical' in detected_categories:
            recommendations.append("🚨🚨 CRITICAL: This is very likely a scam call! HANG UP IMMEDIATELY!")
            recommendations.append("🔐 NEVER share your PIN, password, or OTP with anyone - EVER!")
        elif score >= 60:
            recommendations.append("🚨 DELETE this call from your records and BLOCK the number")
            recommendations.append("❌ DO NOT send any money or share any personal information")
        elif score >= 30:
            recommendations.append("⚠️ Verify the caller's identity through official channels")
            recommendations.append("📞 Hang up and call back using official numbers from their website")
        else:
            recommendations.append("✅ Always verify unexpected calls through official channels")
        
        if 'impersonation' in detected_categories:
            recommendations.append("🏢 This caller is impersonating a legitimate organization")
            recommendations.append("📱 Find the official number on their website and call back")
        
        if any('money' in w.lower() for w in warnings):
            recommendations.append("💰 NEVER send money to unknown callers, regardless of the story")
        
        if any('pin' in w.lower() or 'password' in w.lower() for w in warnings):
            recommendations.append("🔐 NO legitimate organization will ever ask for your PIN or password")
        
        recommendations.append("📞 Report scam calls to your service provider by forwarding the number to 333 (Safaricom) or 3333 (Airtel)")
        
        # Remove duplicates
        recommendations = list(dict.fromkeys(recommendations))[:6]
        
        # ============ DETERMINE RISK LEVEL ============
        if score >= 70:
            risk_level = "CRITICAL - SCAM CALL CONFIRMED"
            color = "danger"
            emoji = "🔴🚨🚨"
            message = "⚠️⚠️ CRITICAL: This call shows overwhelming scam indicators! HANG UP NOW!"
        elif score >= 50:
            risk_level = "HIGH RISK - SCAM CALL DETECTED"
            color = "danger"
            emoji = "🔴🚨"
            message = "⚠️ This call shows strong scam indicators! HANG UP immediately."
        elif score >= 25:
            risk_level = "MEDIUM RISK - SUSPICIOUS"
            color = "warning"
            emoji = "🟡⚠️"
            message = "⚠️ This call has suspicious elements. Verify through official channels before taking any action."
        else:
            risk_level = "LOW RISK - LIKELY SAFE"
            color = "success"
            emoji = "🟢✅"
            message = "✓ No scam patterns detected, but always exercise caution with unexpected calls."
        
        return {
            'score': round(score, 1),
            'risk_level': risk_level,
            'color': color,
            'emoji': emoji,
            'message': message,
            'warnings': warnings[:12],
            'recommendations': recommendations[:6],
            'detected_categories': list(set(detected_categories)),
            'impersonations': detected_impersonations[:3],
            'transcript_length': len(transcript),
            'confidence': round(confidence, 1),
            'type': 'CALL',
            'phrase_matches': phrase_matches[:5]
        }
    
    def report_scam_number(self, phone_number: str, description: str = '') -> Dict:
        """Report a scam phone number to the database"""
        cleaned = re.sub(r'\D', '', str(phone_number))
        
        if cleaned not in self.reported_scam_numbers:
            self.reported_scam_numbers.add(cleaned)
            
            # Update pattern memory
            if cleaned not in self.pattern_memory:
                self.pattern_memory[cleaned] = {'reports': 0, 'first_seen': datetime.now().isoformat()}
            self.pattern_memory[cleaned]['reports'] += 1
            self.pattern_memory[cleaned]['last_reported'] = datetime.now().isoformat()
            if description:
                self.pattern_memory[cleaned]['description'] = description[:200]
            
            # Save to persistent storage
            self._save_reported_scams()
            
            return {
                'status': 'success',
                'message': f'Thank you for reporting! Number {cleaned} has been added to our scam database.',
                'number': cleaned,
                'total_reports': self.pattern_memory[cleaned]['reports']
            }
        else:
            return {
                'status': 'info',
                'message': f'Number {cleaned} has already been reported. Thank you for helping keep others safe!',
                'number': cleaned,
                'total_reports': self.pattern_memory.get(cleaned, {}).get('reports', 1)
            }
    
    def get_scam_statistics(self) -> Dict:
        """Get statistics about reported scam numbers"""
        return {
            'total_reported_numbers': len(self.reported_scam_numbers),
            'most_reported': sorted(self.pattern_memory.items(), key=lambda x: x[1].get('reports', 0), reverse=True)[:10],
            'last_updated': datetime.now().isoformat()
        }

# Create singleton instance
phone_detector = PhoneScamDetector()


def detect_call_scam(transcript: str, phone_number: str = None) -> Dict:
    """Main function for call scam detection with enhanced accuracy"""
    result = phone_detector.analyze_call_transcript(transcript)
    
    if phone_number:
        number_analysis = phone_detector.analyze_phone_number(phone_number)
        result['number_analysis'] = number_analysis
        
        # Combine scores with weighted average
        combined_score = (result['score'] * 0.7) + (number_analysis['score'] * 0.3)
        result['combined_score'] = round(combined_score, 1)
        result['score'] = round(combined_score, 1)  # Use combined score as primary
        
        # Adjust risk level based on combined score
        if combined_score >= 70:
            result['risk_level'] = "CRITICAL - SCAM CALL CONFIRMED"
            result['color'] = "danger"
            result['emoji'] = "🔴🚨🚨"
            result['message'] = "⚠️⚠️ CRITICAL: Both the number and conversation indicate a scam! HANG UP NOW!"
        elif combined_score >= 50:
            result['risk_level'] = "HIGH RISK - SCAM CALL DETECTED"
            result['color'] = "danger"
            result['emoji'] = "🔴🚨"
    
    return result


def check_phone_number(phone_number: str) -> Dict:
    """Check a phone number for scam indicators"""
    return phone_detector.analyze_phone_number(phone_number)


def report_scam_call_number(phone_number: str, description: str = '') -> Dict:
    """Report a scam phone number to help protect others"""
    return phone_detector.report_scam_number(phone_number, description)


def get_scam_statistics() -> Dict:
    """Get scam detection statistics"""
    return phone_detector.get_scam_statistics()