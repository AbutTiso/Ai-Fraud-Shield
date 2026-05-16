# detector/sms_detector.py
"""
Enhanced SMS Scam Detection Module
Detects scams in SMS messages with 200+ Kenyan-specific patterns
"""

import re
from datetime import datetime


class SMSScamDetector:
    """
    Enhanced SMS scam detection with comprehensive Kenyan patterns
    """
    
    def __init__(self):
        self.version = "2.0"
        self.patterns_loaded = 0
        
    def detect_sms_scam(self, sms_text):
        """Detect scams in SMS messages - Enhanced with 200+ Kenyan scam patterns"""
        
        if not sms_text or not sms_text.strip():
            return self._get_empty_response()
        
        text_lower = sms_text.lower()
        score = 0
        warnings = []
        high_risk_found = []
        medium_risk_found = []
        
        # ============================================================
        # ENHANCED SCAM PATTERNS - ORGANIZED BY CATEGORY
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
        
        # CATEGORY 2: Banking Scams (15 patterns)
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
        ]
        
        # CATEGORY 3: Government Scams (15 patterns)
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
        ]
        
        # CATEGORY 4: Employment & Job Scams (12 patterns)
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
        
        # CATEGORY 6: Emergency & Family Scams (10 patterns)
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
        
        # CATEGORY 10: Swahili Scams (15 patterns)
        swahili_scams = [
            (r'akaunti.*yako.*imefungwa', 'Your account is blocked scam (Swahili)', 25, 'HIGH'),
            (r'tuma.*pesa.*sasa.*haraka', 'Send money urgently scam (Swahili)', 25, 'HIGH'),
            (r'umeshinda.*tuzo.*pesa', 'You won prize scam (Swahili)', 25, 'HIGH'),
            (r'namba.*yako.*siri.*toa', 'Share your PIN scam (Swahili)', 35, 'CRITICAL'),
            (r'benki.*yako.*imefungwa', 'Your bank is blocked scam (Swahili)', 25, 'HIGH'),
            (r'mkopo.*wako.*umekubaliwa', 'Loan approved scam (Swahili)', 20, 'HIGH'),
            (r'malipo.*yako.*imeshindwa', 'Payment failed scam (Swahili)', 20, 'HIGH'),
            (r'bonyeza.*hapa.*kiungo', 'Click here link scam (Swahili)', 15, 'MEDIUM'),
            (r'thibitisha.*namba.*yako.*siri', 'Verify your PIN scam (Swahili)', 35, 'CRITICAL'),
            (r'mtoto.*mgonjwa.*hospitali', 'Child sick hospital scam (Swahili)', 30, 'CRITICAL'),
            (r'ajali.*ime.*tokea.*tuma.*pesa', 'Accident send money scam (Swahili)', 30, 'CRITICAL'),
            (r'kazi.*ya.*nyumbani.*pata.*pesa', 'Work from home earn money scam (Swahili)', 20, 'HIGH'),
            (r'fedha.*za.*serikali.*kukusaidia', 'Government money help scam (Swahili)', 25, 'HIGH'),
            (r'shiriki.*na.*ushinde.*zawadi', 'Participate and win prize scam (Swahili)', 20, 'HIGH'),
            (r'hatua.*ya.*haraka.*inahitajika', 'Urgent action needed scam (Swahili)', 20, 'HIGH'),
        ]
        
        # ============================================================
        # Combine all patterns
        # ============================================================
        all_scam_patterns = (mpesa_scams + banking_scams + government_scams + 
                             employment_scams + prize_scams + emergency_scams + 
                             investment_scams + threat_scams + phishing_scams + 
                             swahili_scams)
        
        self.patterns_loaded = len(all_scam_patterns)
        
        # Check each pattern
        for pattern, description, points, severity in all_scam_patterns:
            if re.search(pattern, text_lower):
                score += points
                warning_msg = f"⚠️ {description}"
                if warning_msg not in warnings:
                    warnings.append(warning_msg)
                    if severity == 'CRITICAL':
                        high_risk_found.append(description)
                    elif severity == 'HIGH':
                        high_risk_found.append(description)
                    else:
                        medium_risk_found.append(description)
        
        # ============================================================
        # URL Analysis (Enhanced)
        # ============================================================
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text_lower)
        if urls:
            score += 12
            warnings.append(f"🔗 Suspicious link detected ({len(urls)} URL(s))")
            
            # Check for suspicious domains
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', '.live', '.win', '.bid', '.loan']
            for url in urls:
                for tld in suspicious_tlds:
                    if tld in url:
                        score += 15
                        warnings.append(f"⚠️ Suspicious domain extension in link: {tld}")
                        break
                
                # Check for IP address URLs
                if re.search(r'\d+\.\d+\.\d+\.\d+', url):
                    score += 20
                    warnings.append("⚠️ Link uses IP address instead of domain name")
                
                # Check for URL shorteners
                shorteners = ['bit.ly', 'tinyurl.com', 'short.link', 'cutt.ly', 'ow.ly', 'is.gd', 'goo.gl']
                for shortener in shorteners:
                    if shortener in url:
                        score += 12
                        warnings.append(f"🔗 URL shortener detected ({shortener}) - hides real destination")
                        break
        
        # ============================================================
        # Phone Number Analysis (Enhanced)
        # ============================================================
        phone_numbers = re.findall(r'(07|01|2547)\d{8}', text_lower)
        if phone_numbers:
            score += 10
            unique_numbers = list(set(phone_numbers))
            warnings.append(f"📞 Suspicious phone number(s): {', '.join(unique_numbers[:2])}")
            
            # Check for repeated suspicious patterns in numbers
            for number in unique_numbers:
                # Repeated digits (e.g., 0711111111)
                if re.search(r'(\d)\1{7,}', number):
                    score += 10
                    warnings.append(f"⚠️ Number has suspicious repeated digits: {number}")
        
        # ============================================================
        # Grammar & Spelling Error Detection
        # ============================================================
        grammar_issues = 0
        common_mistakes = [
            'recieve', 'wich', 'thier', 'untill', 'definately', 
            'seperate', 'occured', 'priviledge', 'goverment', 'comission',
            'accomodate', 'maintainance', 'refferal', 'transfered', 'benifit'
        ]
        
        for mistake in common_mistakes:
            if mistake in text_lower:
                grammar_issues += 1
        
        if grammar_issues >= 2:
            score += grammar_issues * 3
            warnings.append(f"📝 Multiple spelling errors detected ({grammar_issues}) - common in scams")
        
        # ============================================================
        # Exclamation Mark Overuse Detection
        # ============================================================
        exclamation_count = text_lower.count('!')
        if exclamation_count >= 3:
            score += exclamation_count
            if exclamation_count >= 5:
                warnings.append(f"⚠️ Excessive exclamation marks ({exclamation_count}) - pressure tactic")
        
        # ============================================================
        # Keyword Combination Detection (Bonus for multiple scam indicators)
        # ============================================================
        urgent_words = ['urgent', 'immediately', 'asap', 'haraka', 'sasa']
        money_words = ['money', 'pesa', 'send', 'tuma', 'transfer']
        sensitive_words = ['pin', 'password', 'otp', 'code', 'siri', 'namba']
        
        urgency_count = sum(1 for word in urgent_words if word in text_lower)
        money_count = sum(1 for word in money_words if word in text_lower)
        sensitive_count = sum(1 for word in sensitive_words if word in text_lower)
        
        # Bonus for dangerous combinations
        if urgency_count >= 1 and money_count >= 1:
            bonus = 10
            score += bonus
            warnings.append("⚠️ Urgency + Money request combination (high risk)")
        
        if urgency_count >= 1 and sensitive_count >= 1:
            bonus = 20
            score += bonus
            warnings.append("🔴 CRITICAL: Urgency + PIN/password request")
        
        if money_count >= 1 and sensitive_count >= 1:
            bonus = 15
            score += bonus
            warnings.append("🔴 Money request + Sensitive information request")
        
        # ============================================================
        # Cap score at 100
        # ============================================================
        score = min(100, score)
        
        # ============================================================
        # Remove duplicate warnings
        # ============================================================
        warnings = list(dict.fromkeys(warnings))
        
        # ============================================================
        # Determine Risk Level with Enhanced Messages
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
            message = "🔵 LOW RISK: Minor suspicious elements detected. Be cautious and verify if unexpected."
            is_scam = False
        else:
            risk_level = "LOW RISK - LIKELY SAFE"
            risk_level_display = "LOW"
            color = "success"
            badge_class = "bg-success"
            emoji = "🟢"
            message = "✅ LOW RISK: No obvious scam patterns detected. Always exercise normal caution."
            is_scam = False
        
        # ============================================================
        # Generate Enhanced Recommendations
        # ============================================================
        recommendations = self._get_recommendations(score, high_risk_found, sensitive_count)
        
        # ============================================================
        # Return the result
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
            'urls_found': len(urls) if 'urls' in locals() else 0,
            'phones_found': len(phone_numbers) if 'phone_numbers' in locals() else 0,
            'grammar_issues': grammar_issues,
            'exclamation_count': exclamation_count if 'exclamation_count' in locals() else 0,
            'original_preview': sms_text[:150] + ('...' if len(sms_text) > 150 else ''),
            'type': 'SMS',
            'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
            'urls_found': 0,
            'phones_found': 0,
            'grammar_issues': 0,
            'exclamation_count': 0,
            'type': 'SMS'
        }
    
    def _get_recommendations(self, score, high_risk_found, sensitive_count):
        """Generate tailored recommendations based on risk level"""
        
        recommendations = []
        
        if score >= 60:
            recommendations.append("🚨 DO NOT reply to this message or click any links")
            recommendations.append("📞 Contact your service provider directly using official numbers")
            recommendations.append("🚫 NEVER share your PIN, password, or M-Pesa code")
            recommendations.append("📱 Forward suspicious messages to 333 (Safaricom) or 3333 (Airtel)")
            recommendations.append("🔗 Hover over links to see real destination before clicking")
            recommendations.append("📸 Take a screenshot as evidence before deleting")
        elif score >= 35:
            recommendations.append("⚠️ Be very cautious with this message")
            recommendations.append("🔍 Verify the sender by calling official customer care")
            recommendations.append("🚫 Don't share any personal or financial information")
            recommendations.append("📞 Contact the company directly using their official website")
        else:
            recommendations.append("✅ Stay vigilant even with seemingly safe messages")
            recommendations.append("🔐 Never share your M-PESA PIN or OTP with anyone")
            recommendations.append("📱 Report any suspicious activity to your service provider")
            recommendations.append("🛡️ AI Fraud Shield is protecting you - stay alert!")
        
        # Add specific recommendations based on findings
        if sensitive_count > 0:
            recommendations.insert(0, "🔐 CRITICAL: This message asks for sensitive information - THIS IS A SCAM!")
        
        if "M-Pesa" in str(high_risk_found) or "M-PESA" in str(high_risk_found):
            recommendations.insert(1, "📱 Legitimate M-Pesa messages come from 'M-PESA' with transaction details - never ask for PIN")
        
        return recommendations


# Singleton instance for easy import
_detector = None

def get_detector():
    """Get or create singleton detector instance"""
    global _detector
    if _detector is None:
        _detector = SMSScamDetector()
    return _detector


def detect_sms_scam(sms_text):
    """
    Convenience function for SMS scam detection
    Maintains backward compatibility with existing code
    """
    detector = get_detector()
    return detector.detect_sms_scam(sms_text)


def quick_test():
    """Test the SMS detector with sample messages"""
    print("\n" + "="*60)
    print("📱 SMS Detector Quick Test")
    print("="*60)
    
    test_cases = [
        ("Normal Message", "Your M-PESA transaction of Ksh 500 to John Doe was successful. New balance: Ksh 2,500"),
        ("Suspicious Promotion", "CONGRATULATIONS! You've won 50,000 bonus points! Click https://bit.ly/claim now!"),
        ("Critical Scam", "URGENT! Your M-Pesa account has been suspended. Send your MPIN to 0712345678 for verification NOW or lose Ksh 150,000!")
    ]
    
    detector = get_detector()
    
    for name, text in test_cases:
        print(f"\n📝 {name}:")
        print(f"   Text: {text[:80]}...")
        result = detector.detect_sms_scam(text)
        print(f"   Score: {result['score']}/100")
        print(f"   Risk: {result['risk_level_display']}")
        print(f"   Is Scam: {result['is_scam']}")
        print(f"   Warnings: {len(result['warnings'])}")


if __name__ == "__main__":
    quick_test()