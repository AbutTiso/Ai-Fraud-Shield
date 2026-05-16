# detector/whatsapp_detector.py
"""
WhatsApp Scam Detection Module
Detects scams in exported WhatsApp chats with Kenyan-specific patterns
"""

import re
from datetime import datetime, timedelta
from collections import Counter


class WhatsAppScamDetector:
    """
    Enhanced WhatsApp scam detection with advanced pattern matching
    """
    
    def __init__(self):
        # Common WhatsApp scam patterns in Kenya with weights
        self.scam_patterns = [
            # Financial scams
            (r'send.*?money.*?to.*?\d{10}', 'Money request with phone number', 15),
            (r'urgent.*?help.*?money', 'Urgent money request', 12),
            (r'ksh\s*[\d,]+\s*(?:million|m|thousand|k)', 'Large money amount mentioned', 12),
            (r'tuma.*?pesa.*?\d+', 'Swahili money request', 15),
            
            # Prize/lottery scams
            (r'free.*?prize.*?click', 'Fake prize/lottery', 18),
            (r'win.*?iphone.*?safaricom', 'Fake Safaricom iPhone promotion', 20),
            (r'congratulations.*?selected', 'Fake congratulations message', 15),
            (r'you.*?won.*?\d+.*?ksh', 'Lottery winning claim', 18),
            
            # Account scams
            (r'verify.*?account.*?link', 'Account verification scam', 15),
            (r'account.*?suspended.*?click', 'Account suspension threat', 20),
            (r'whatsapp.*?gold.*?number', 'WhatsApp gold scam', 20),
            
            # Job scams
            (r'job.*?opportunity.*?pay.*?first', 'Fake job requiring payment', 15),
            (r'work.*?from.*?home.*?earn', 'Work from home scam', 12),
            (r'data entry.*?job.*?registration', 'Fake data entry job', 12),
            
            # Loan scams
            (r'loan.*?offer.*?processing.*?fee', 'Fake loan advance fee', 18),
            (r'instant loan.*?no.*?credit', 'Fake instant loan offer', 12),
            (r'fuliza.*?limit.*?increase', 'Fake Fuliza upgrade scam', 20),
            (r'm-shwari.*?bonus', 'Fake M-Shwari bonus', 18),
            
            # Investment scams
            (r'investment.*?double.*?money', 'Ponzi scheme', 20),
            (r'bitcoin.*?investment.*?return', 'Cryptocurrency scam', 18),
            (r'forex.*?trading.*?profit', 'Forex trading scam', 15),
            
            # Gift card scams
            (r'gift.*?card.*?send.*?code', 'Gift card scam', 15),
            (r'google.*?play.*?card', 'Google Play card scam', 12),
            
            # Urgency tactics
            (r'limited.*?time.*?offer', 'Urgency pressure tactic', 10),
            (r'last.*?chance.*?expires', 'False urgency', 12),
            (r'act.*?now.*?immediately', 'Immediate action pressure', 10),
            
            # Link scams
            (r'click.*?link.*?claim', 'Link claiming scam', 12),
            (r'http[s]?://bit\.ly|tinyurl|short\.link', 'Shortened URL scam', 15),
            
            # Personal info requests
            (r'pin|password|mpin|otp', 'PIN/Password request', 25),
            (r'verify.*?identity.*?send', 'Identity verification request', 20),
            (r'update.*?your.*?details', 'Personal info update request', 15),
            
            # Family emergency scams
            (r'mtoto.*?hospital.*?tuma.*?pesa', 'Child hospital emergency', 25),
            (r'mama.*?accident.*?money', 'Parent accident scam', 25),
            (r'emergency.*?send.*?money.*?now', 'Emergency money request', 20),
            
            # Brand impersonation
            (r'safaricom.*?(?:reward|points|cashback)', 'Fake Safaricom reward', 20),
            (r'airtel.*?(?:reward|points|cashback)', 'Fake Airtel reward', 20),
            (r'telkom.*?(?:reward|points|cashback)', 'Fake Telkom reward', 20),
            (r'kcb.*?(?:loan|reward|bonus)', 'Fake KCB offer', 18),
            (r'equity.*?(?:loan|reward|bonus)', 'Fake Equity offer', 18),
            
            # Wrong number openers
            (r'hello dear|dear customer|dear user', 'Generic greeting - mass message', 8),
            (r"I am (?:Mr|Mrs|Dr|Prof|Eng)\.?\s+\w+", 'Title prefix - potential scammer', 8),
            (r'how are you doing today', 'Fake friendly opener', 5),
        ]
        
        # Legitimate patterns (reduce score)
        self.legitimate_patterns = [
            (r'thank you for (?:using|shopping|banking|choosing)', 'Thank you message', -5),
            (r'receipt no\.?\s*[A-Z0-9]{6,}', 'Official receipt number', -5),
            (r'your (?:transaction|payment|transfer) was successful', 'Transaction success', -5),
            (r'balance:?.*ksh', 'Balance inquiry', -3),
        ]
        
        # Suspicious keywords with weights
        self.suspicious_keywords = {
            'urgent': 10, 'immediately': 10, 'haraka': 10, 'sasa': 8,
            'verify': 12, 'confirm': 10, 'update': 8, 'reactivate': 10,
            'suspended': 15, 'blocked': 15, 'locked': 15, 'deactivated': 15,
            'pin': 20, 'password': 20, 'otp': 20, 'code': 15, 'siri': 20,
            'send money': 15, 'tuma pesa': 15, 'mpesa': 12, 'fuliza': 15,
            'winner': 15, 'prize': 12, 'congratulations': 12, 'claim': 10,
            'free': 8, 'bonus': 8, 'reward': 8, 'cashback': 8,
        }
    
    def detect_whatsapp_scam(self, chat_text):
        """Detect scams in exported WhatsApp chats"""
        
        if not chat_text or not chat_text.strip():
            return self._get_empty_response()
        
        lines = chat_text.split('\n')
        score = 0
        warnings = []
        suspicious_messages = []
        unique_senders = set()
        sender_message_count = Counter()
        urls_found = []
        phone_numbers_found = []
        
        # Parse chat lines
        for i, line in enumerate(lines):
            if not line.strip():
                continue
                
            line_lower = line.lower()
            
            # Extract sender info
            match = re.match(r'(\d{1,2}/\d{1,2}/\d{4}), (\d{1,2}:\d{2}) - ([^:]+):', line)
            if match:
                sender = match.group(3).strip()
                unique_senders.add(sender)
                sender_message_count[sender] += 1
                # Remove timestamp for content analysis
                content = line[match.end():].strip()
            else:
                content = line
            
            # Check scam patterns
            for pattern, description, points in self.scam_patterns:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    score += points
                    warning_msg = f"Line {i+1}: {description}"
                    if warning_msg not in warnings:
                        warnings.append(f"⚠️ {warning_msg}")
                        if len(suspicious_messages) < 5:
                            suspicious_messages.append(content[:100])
            
            # Check legitimate patterns (reduce score)
            for pattern, description, points in self.legitimate_patterns:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    score = max(0, score + points)  # points are negative
            
            # Check suspicious keywords
            for keyword, points in self.suspicious_keywords.items():
                if keyword in line_lower:
                    score += points
                    if f"'{keyword}'" not in str(warnings):
                        warnings.append(f"⚠️ Contains suspicious keyword: '{keyword}'")
            
            # Check for URLs
            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', line)
            if urls:
                for url in urls:
                    urls_found.append(url)
                    score += 8
                    # Check for suspicious TLDs
                    if any(tld in url for tld in ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']):
                        score += 12
                        warnings.append("⚠️ Suspicious domain extension in URL")
                
                if "URL" not in str(warnings):
                    warnings.append(f"🔗 {len(urls)} suspicious link(s) detected")
            
            # Check for phone numbers
            phones = re.findall(r'(?:07|01|2547)\d{8}', line)
            if phones:
                phone_numbers_found.extend(phones)
                score += 10
                if "Phone number" not in str(warnings):
                    warnings.append(f"📞 Unsolicited phone number(s): {', '.join(set(phones[:2]))}")
            
            # Check for money amounts
            money_amounts = re.findall(r'(?:ksh|kes|shillings?)\s*[\d,]+', line_lower)
            if money_amounts:
                score += 10
                if "Money request" not in str(warnings):
                    warnings.append(f"💰 Money amount detected: {money_amounts[0].upper()}")
            
            # Check for personal info requests (HIGH priority)
            if re.search(r'\b(?:pin|password|mpin|otp|siri|namba ya siri)\b', line_lower):
                score += 25
                warnings.append("🔐 CRITICAL: Request for sensitive information - DEFINITE SCAM!")
        
        # Additional analysis
        
        # Check for single sender dominance (spam campaign)
        if len(unique_senders) == 1 and len(lines) > 20:
            score += 15
            warnings.append("📨 Single sender with many messages - potential spam campaign")
        
        # Check for suspicious sender name patterns
        for sender in unique_senders:
            if re.search(r'(?:customer care|support|help desk|admin|official)', sender.lower()):
                score += 10
                warnings.append(f"👤 Suspicious sender name: '{sender}'")
        
        # Check message frequency (potential bot)
        total_messages = len([l for l in lines if re.match(r'\d{1,2}/\d{1,2}/\d{4}', l)])
        if total_messages > 50 and len(unique_senders) < 3:
            score += 10
            warnings.append("🤖 High message volume from few senders - possible automated scam")
        
        # Check for group invites
        if 'added you' in chat_text.lower() or 'group' in chat_text.lower():
            score += 8
            if "Group invite" not in str(warnings):
                warnings.append("👥 Unexpected group add - potential scam group")
        
        # Check for grammar issues (common in scams)
        grammar_errors = 0
        common_errors = ['recieve', 'wich', 'thier', 'untill', 'definately', 'seperate']
        for error in common_errors:
            if error in chat_text.lower():
                grammar_errors += 1
        if grammar_errors >= 2:
            score += 8
            warnings.append(f"📝 Multiple spelling errors ({grammar_errors}) - common in scams")
        
        # Exclamation mark overuse
        exclamation_count = chat_text.count('!')
        if exclamation_count >= 5:
            score += 5
            warnings.append(f"⚠️ Excessive exclamation marks ({exclamation_count}) - urgency tactic")
        
        # Cap score at 100
        score = min(100, score)
        
        # Remove duplicate warnings
        warnings = list(dict.fromkeys(warnings))
        
        # Determine risk level and response
        return self._get_risk_response(score, warnings, suspicious_messages, 
                                       unique_senders, total_messages, urls_found, phone_numbers_found)
    
    def _get_empty_response(self):
        """Return empty response for no input"""
        return {
            'score': 0,
            'risk_level': 'NO DATA',
            'color': 'secondary',
            'emoji': '⚪',
            'message': 'No chat content provided for analysis',
            'warnings': ['Please provide WhatsApp chat text to analyze'],
            'recommendations': ['Export your WhatsApp chat and paste it here'],
            'suspicious_messages': [],
            'message_count': 0,
            'unique_senders': 0,
            'urls_found': [],
            'phones_found': [],
            'type': 'WHATSAPP'
        }
    
    def _get_risk_response(self, score, warnings, suspicious_messages, 
                          unique_senders, message_count, urls_found, phones_found):
        """Generate risk-based response"""
        
        if score >= 70:
            return {
                'score': score,
                'risk_level': 'CRITICAL - SCAM CONFIRMED',
                'risk_level_display': 'CRITICAL',
                'color': 'danger',
                'badge_class': 'bg-danger',
                'emoji': '🔴🚨',
                'message': '🔴 CRITICAL: This WhatsApp chat is a DEFINITE SCAM! Do NOT engage!',
                'warnings': warnings[:8],
                'recommendations': [
                    '🚨 BLOCK the sender immediately',
                    '📞 Report the number to your service provider (333 for Safaricom, 3333 for Airtel)',
                    '🚫 NEVER send money or share personal information',
                    '📸 Take screenshots as evidence before blocking',
                    '🔗 DO NOT click any links in the chat',
                    '📢 Warn your contacts about this scammer'
                ],
                'suspicious_messages': suspicious_messages[:5],
                'message_count': message_count,
                'unique_senders': len(unique_senders),
                'urls_found': urls_found[:3],
                'phones_found': list(set(phones_found))[:3],
                'type': 'WHATSAPP',
                'is_scam': True
            }
        elif score >= 50:
            return {
                'score': score,
                'risk_level': 'HIGH RISK - SCAM DETECTED',
                'risk_level_display': 'HIGH',
                'color': 'danger',
                'badge_class': 'bg-danger',
                'emoji': '🔴',
                'message': '🔴 HIGH RISK: This WhatsApp chat contains multiple scam indicators!',
                'warnings': warnings[:8],
                'recommendations': [
                    '⚠️ BLOCK the sender immediately',
                    '📞 Report to your service provider',
                    '🚫 Never send money or share personal information',
                    '🔗 Do not click any links',
                ],
                'suspicious_messages': suspicious_messages[:5],
                'message_count': message_count,
                'unique_senders': len(unique_senders),
                'urls_found': urls_found[:3],
                'phones_found': list(set(phones_found))[:3],
                'type': 'WHATSAPP',
                'is_scam': True
            }
        elif score >= 30:
            return {
                'score': score,
                'risk_level': 'MEDIUM RISK - SUSPICIOUS',
                'risk_level_display': 'MEDIUM',
                'color': 'warning',
                'badge_class': 'bg-warning',
                'emoji': '🟡',
                'message': '⚠️ MEDIUM RISK: This chat has suspicious elements. Verify before trusting.',
                'warnings': warnings[:6],
                'recommendations': [
                    '⚠️ Be very cautious with this conversation',
                    '🔍 Verify the sender\'s identity through another channel',
                    '🚫 Don\'t share any personal or financial information',
                    '📞 Call the person directly to verify if it\'s really them',
                ],
                'suspicious_messages': suspicious_messages[:3],
                'message_count': message_count,
                'unique_senders': len(unique_senders),
                'urls_found': urls_found[:2],
                'phones_found': list(set(phones_found))[:2],
                'type': 'WHATSAPP',
                'is_scam': False
            }
        elif score >= 15:
            return {
                'score': score,
                'risk_level': 'LOW RISK - CAUTION',
                'risk_level_display': 'LOW',
                'color': 'info',
                'badge_class': 'bg-info',
                'emoji': '🔵',
                'message': '🔵 LOW RISK: Minor suspicious elements detected. Stay vigilant.',
                'warnings': warnings[:4],
                'recommendations': [
                    '✅ Stay vigilant even with seemingly safe messages',
                    '🔐 Never share your M-PESA PIN or OTP with anyone',
                    '📱 Report any suspicious activity to your service provider',
                ],
                'suspicious_messages': suspicious_messages[:2],
                'message_count': message_count,
                'unique_senders': len(unique_senders),
                'urls_found': urls_found[:1],
                'phones_found': list(set(phones_found))[:1],
                'type': 'WHATSAPP',
                'is_scam': False
            }
        else:
            return {
                'score': score,
                'risk_level': 'LOW RISK - LIKELY SAFE',
                'risk_level_display': 'LOW',
                'color': 'success',
                'badge_class': 'bg-success',
                'emoji': '🟢',
                'message': '✅ LOW RISK: No obvious scam patterns detected.',
                'warnings': warnings[:3] if warnings else ['✅ No scam indicators found'],
                'recommendations': [
                    '✅ Keep up with security awareness',
                    '🔐 Always verify unexpected requests',
                    '📱 Report any suspicious activity',
                ],
                'suspicious_messages': [],
                'message_count': message_count,
                'unique_senders': len(unique_senders),
                'urls_found': [],
                'phones_found': [],
                'type': 'WHATSAPP',
                'is_scam': False
            }


# Singleton instance for easy import
_detector = None

def get_detector():
    """Get or create singleton detector instance"""
    global _detector
    if _detector is None:
        _detector = WhatsAppScamDetector()
    return _detector


def detect_whatsapp_scam(chat_text):
    """
    Convenience function for WhatsApp scam detection
    Maintains backward compatibility with existing code
    """
    detector = get_detector()
    return detector.detect_whatsapp_scam(chat_text)


# For backward compatibility with old function name
def detect_whatsapp_builtin(chat_text):
    """Alias for detect_whatsapp_scam (backward compatibility)"""
    return detect_whatsapp_scam(chat_text)


def quick_test():
    """Test the WhatsApp detector with sample messages"""
    print("\n" + "="*60)
    print("📱 WhatsApp Detector Quick Test")
    print("="*60)
    
    test_cases = [
        ("Normal message", "Hello, how are you doing today?"),
        ("Scam - Urgent money", "URGENT! My child is in hospital. Please send Ksh 10,000 to 0712345678"),
        ("Scam - Prize", "CONGRATULATIONS! You've won an iPhone 15. Click https://bit.ly/claim to claim your prize!"),
        ("Scam - Loan", "LOAN OFFER: Get instant loan up to Ksh 500,000. Processing fee Ksh 1,000 required."),
        ("Scam - Fuliza", "Your Fuliza limit has been increased to Ksh 50,000. Verify your account now: send PIN to 0712345678"),
    ]
    
    detector = get_detector()
    
    for name, text in test_cases:
        print(f"\n📝 Test: {name}")
        print(f"   Text: {text[:80]}...")
        result = detector.detect_whatsapp_scam(text)
        print(f"   Score: {result['score']}/100")
        print(f"   Risk: {result['risk_level_display']}")
        print(f"   Warnings: {len(result['warnings'])}")
        print(f"   Is Scam: {result.get('is_scam', False)}")


if __name__ == "__main__":
    quick_test()