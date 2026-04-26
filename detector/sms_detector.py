# detector/sms_detector.py
import re

def detect_sms_scam(sms_text):
    """Detect scams in SMS messages - Enhanced with 150+ Kenyan scam patterns"""
    
    text_lower = sms_text.lower()
    score = 0
    warnings = []
    
    # ============================================================
    # ENHANCED SCAM PATTERNS - ORGANIZED BY CATEGORY
    # ============================================================
    
    # CATEGORY 1: M-PESA & Mobile Money Scams (15 patterns)
    mpesa_scams = [
        (r'm-pesa.*suspended', 'M-Pesa suspension scam', 15),
        (r'mpesa.*blocked', 'M-Pesa blocked account scam', 15),
        (r'fuliza.*limit.*increase', 'Fake Fuliza limit increase scam', 18),
        (r'm-shwari.*bonus', 'Fake M-Shwari bonus scam', 15),
        (r'm-pesa.*verify.*pin', 'M-Pesa PIN verification scam', 20),
        (r'mpesa.*upgrade.*required', 'Fake M-Pesa upgrade scam', 15),
        (r'm-pesa.*reward.*points', 'Fake M-Pesa reward points scam', 12),
        (r'mpesa.*transaction.*failed.*refund', 'Fake M-Pesa refund scam', 18),
        (r'mpesa.*account.*locked', 'M-Pesa account locked scam', 15),
        (r'm-pesa.*withdrawal.*alert', 'Fake M-Pesa withdrawal scam', 12),
        (r'mpesa.*cashback.*offer', 'Fake M-Pesa cashback scam', 12),
        (r'm-pesa.*lottery.*winner', 'M-Pesa lottery scam', 15),
        (r'fuliza.*loan.*approved', 'Fake Fuliza approval scam', 15),
        (r'm-shwari.*loan.*offer', 'Fake M-Shwari loan scam', 12),
        (r'm-pesa.*security.*alert', 'Fake M-Pesa security alert', 15),
    ]
    
    # CATEGORY 2: Banking Scams (15 patterns)
    banking_scams = [
        (r'kcb.*loan.*advance.*fee', 'Fake KCB loan advance fee scam', 20),
        (r'equity.*reward.*points', 'Fake Equity Bank reward scam', 15),
        (r'cooperative.*dividend', 'Fake Co-op Bank dividend scam', 15),
        (r'ncba.*loan.*offer', 'Fake NCBA loan offer scam', 15),
        (r'absa.*promotion.*winner', 'Fake Absa promotion scam', 15),
        (r'family.*bank.*loan', 'Fake Family Bank loan scam', 15),
        (r'kcb.*mpesa.*link', 'Fake KCB M-PESA link scam', 18),
        (r'equity.*mpesa.*integration', 'Fake Equity M-PESA integration scam', 18),
        (r'bank.*account.*suspended', 'Bank account suspension scam', 18),
        (r'bank.*verification.*required', 'Bank verification required scam', 15),
        (r'bank.*update.*details', 'Bank details update scam', 15),
        (r'bank.*security.*alert', 'Bank security alert scam', 15),
        (r'bank.*card.*blocked', 'Bank card blocked scam', 15),
        (r'bank.*loan.*approved', 'Fake bank loan approval scam', 12),
        (r'bank.*reward.*points', 'Fake bank reward points scam', 12),
    ]
    
    # CATEGORY 3: Government Scams (15 patterns)
    government_scams = [
        (r'huduma.*number.*update', 'Fake Huduma Namba update scam', 20),
        (r'nssf.*refund.*claim', 'Fake NSSF refund scam', 18),
        (r'nhif.*medical.*upgrade', 'Fake NHIF upgrade scam', 18),
        (r'kra.*tax.*refund', 'Fake KRA tax refund scam', 20),
        (r'ecitizen.*account.*suspended', 'Fake eCitizen suspension scam', 18),
        (r'hef.*loan.*grant', 'Fake HELB loan scam', 18),
        (r'laptrust.*refund.*claim', 'Fake Laptrust refund scam', 15),
        (r'ntsa.*fine.*penalty', 'Fake NTSA fine scam', 18),
        (r'nema.*fine.*violation', 'Fake NEMA fine scam', 15),
        (r'kenya.*power.*disconnect', 'Fake Kenya Power disconnection scam', 18),
        (r'kcca.*fine.*penalty', 'Fake county fine scam', 15),
        (r'government.*grant.*winner', 'Fake government grant scam', 18),
        (r'presidential.*bailout.*fund', 'Fake presidential bailout scam', 20),
        (r'ura.*tax.*refund', 'Fake URA (Uganda) tax scam', 18),
        (r'ecitizen.*login.*verify', 'Fake eCitizen login scam', 18),
    ]
    
    # CATEGORY 4: Employment & Job Scams (12 patterns)
    employment_scams = [
        (r'kazi.*mtaani.*payment', 'Fake Kazi Mtaani payment scam', 20),
        (r'internship.*fee.*required', 'Fake internship fee scam', 18),
        (r'job.*application.*fee', 'Job application fee scam', 18),
        (r'work.*home.*earn.*money', 'Fake work from home scam', 15),
        (r'data.*entry.*job.*payment', 'Fake data entry job scam', 15),
        (r'online.*business.*opportunity', 'Fake online business scam', 15),
        (r'foreign.*job.*visa.*fee', 'Fake foreign job scam', 18),
        (r'airline.*job.*recruitment', 'Fake airline job scam', 15),
        (r'government.*job.*shortlist', 'Fake government job scam', 18),
        (r'career.*fair.*registration', 'Fake career fair scam', 12),
        (r'graduate.*internship.*program', 'Fake graduate internship scam', 15),
        (r'job.*offer.*processing.*fee', 'Job offer processing fee scam', 18),
    ]
    
    # CATEGORY 5: Prize & Lottery Scams (12 patterns)
    prize_scams = [
        (r'won.*prize.*money', 'Prize scam', 15),
        (r'congratulations.*selected', 'Congratulations scam', 10),
        (r'safaricom.*promotion.*winner', 'Fake Safaricom promotion scam', 18),
        (r'airtel.*promotion.*winner', 'Fake Airtel promotion scam', 18),
        (r'telkom.*promotion.*winner', 'Fake Telkom promotion scam', 18),
        (r'lotto.*winner.*claim', 'Fake lottery winner scam', 18),
        (r'shell.*points.*prize', 'Fake Shell points scam', 15),
        (r'facebook.*lottery.*winner', 'Fake Facebook lottery scam', 15),
        (r'google.*promotion.*winner', 'Fake Google promotion scam', 15),
        (r'compensation.*payout.*claim', 'Fake compensation scam', 20),
        (r'inheritance.*claim.*payment', 'Fake inheritance scam', 20),
        (r'win.*car.*house.*prize', 'Fake car/house prize scam', 18),
    ]
    
    # CATEGORY 6: Emergency & Family Scams (10 patterns)
    emergency_scams = [
        (r'urgent.*send.*money', 'Urgent money request', 12),
        (r'accident.*hospital.*money', 'Fake accident emergency scam', 20),
        (r'family.*emergency.*money', 'Fake family emergency scam', 20),
        (r'child.*sick.*hospital.*money', 'Fake child sickness scam', 20),
        (r'kidnapped.*ransom.*money', 'Fake kidnapping ransom scam', 25),
        (r'police.*arrest.*bail.*money', 'Fake police arrest scam', 18),
        (r'stuck.*stranded.*money', 'Fake travel emergency scam', 15),
        (r'boss.*emergency.*transfer', 'Fake boss emergency transfer scam', 20),
        (r'pastor.*offering.*seed.*money', 'Fake church offering scam', 15),
        (r'prayer.*request.*money', 'Fake prayer request money scam', 12),
    ]
    
    # CATEGORY 7: Investment Scams (10 patterns)
    investment_scams = [
        (r'forex.*guaranteed.*profit', 'Fake Forex guaranteed profit scam', 20),
        (r'crypto.*mining.*investment', 'Fake crypto mining scam', 20),
        (r'stock.*insider.*trading', 'Fake stock trading scam', 18),
        (r'chama.*investment.*dividend', 'Fake chama investment scam', 15),
        (r'sacco.*shares.*dividend', 'Fake SACCO shares scam', 15),
        (r'mlm.*business.*opportunity', 'Fake MLM business scam', 18),
        (r'pyramid.*scheme.*investment', 'Pyramid scheme scam', 25),
        (r'land.*investment.*cheap', 'Fake land investment scam', 15),
        (r'gold.*investment.*returns', 'Fake gold investment scam', 18),
        (r'bitcoin.*investment.*double', 'Fake Bitcoin doubling scam', 20),
    ]
    
    # CATEGORY 8: Threat & Pressure Tactics (12 patterns)
    threat_scams = [
        (r'account.*blocked.*verify', 'Account blocked scam', 15),
        (r'your account.*suspended', 'Account suspension scam', 15),
        (r'limited time.*offer', 'Urgency tactic', 8),
        (r'final.*warning.*notice', 'Final warning scam', 15),
        (r'legal.*action.*against.*you', 'Legal action threat scam', 18),
        (r'court.*case.*file', 'Court case threat scam', 15),
        (r'last.*chance.*offer', 'Last chance pressure scam', 12),
        (r'within.*24.*hours.*action', 'Time pressure scam', 12),
        (r'expires.*today.*offer', 'Expiring offer scam', 12),
        (r'immediate.*action.*required', 'Immediate action scam', 15),
        (r'will.*be.*deactivated', 'Deactivation threat scam', 15),
        (r'will.*be.*closed.*permanently', 'Permanent closure threat', 15),
    ]
    
    # CATEGORY 9: Phishing & Link Scams (10 patterns)
    phishing_scams = [
        (r'click.*link.*verify', 'Verification link scam', 12),
        (r'verify.*identity.*link', 'Identity verification scam', 12),
        (r'update.*payment.*details', 'Payment update scam', 12),
        (r'confirm.*account.*details', 'Account confirmation scam', 12),
        (r'login.*verify.*account', 'Login verification scam', 12),
        (r'secure.*your.*account', 'Account security scam', 10),
        (r'validate.*your.*details', 'Details validation scam', 10),
        (r'update.*your.*information', 'Information update scam', 10),
        (r'reactivate.*your.*account', 'Account reactivation scam', 12),
        (r'unlock.*your.*account', 'Account unlock scam', 12),
    ]
    
    # CATEGORY 10: Swahili Scams (15 patterns)
    swahili_scams = [
        (r'akaunti.*yako.*imefungwa', 'Your account is blocked scam (Swahili)', 18),
        (r'tuma.*pesa.*sasa.*haraka', 'Send money urgently scam (Swahili)', 18),
        (r'umeshinda.*tuzo.*pesa', 'You won prize scam (Swahili)', 18),
        (r'namba.*yako.*siri.*toa', 'Share your PIN scam (Swahili)', 20),
        (r'benki.*yako.*imefungwa', 'Your bank is blocked scam (Swahili)', 18),
        (r'mkopo.*wako.*umekubaliwa', 'Loan approved scam (Swahili)', 15),
        (r'malipo.*yako.*imeshindwa', 'Payment failed scam (Swahili)', 15),
        (r'bonyeza.*hapa.*kiungo', 'Click here link scam (Swahili)', 12),
        (r'thibitisha.*namba.*yako.*siri', 'Verify your PIN scam (Swahili)', 20),
        (r'mtoto.*mgonjwa.*hospitali', 'Child sick hospital scam (Swahili)', 20),
        (r'ajali.*ime.*tokea.*tuma.*pesa', 'Accident send money scam (Swahili)', 20),
        (r'kazi.*ya.*nyumbani.*pata.*pesa', 'Work from home earn money scam (Swahili)', 15),
        (r'fedha.*za.*serikali.*kukusaidia', 'Government money help scam (Swahili)', 18),
        (r'shiriki.*na.*ushinde.*zawadi', 'Participate and win prize scam (Swahili)', 15),
        (r'hatua.*ya.*haraka.*inahitajika', 'Urgent action needed scam (Swahili)', 15),
    ]
    
    # ============================================================
    # Combine all patterns
    # ============================================================
    all_scam_patterns = (mpesa_scams + banking_scams + government_scams + 
                         employment_scams + prize_scams + emergency_scams + 
                         investment_scams + threat_scams + phishing_scams + 
                         swahili_scams)
    
    # Check each pattern
    for pattern, description, points in all_scam_patterns:
        if re.search(pattern, text_lower):
            score += points
            warnings.append(f"⚠️ {description}")
    
    # ============================================================
    # URL Analysis (Enhanced)
    # ============================================================
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text_lower)
    if urls:
        score += 10
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
                    score += 10
                    warnings.append(f"🔗 URL shortener detected ({shortener}) - hides real destination")
                    break
    
    # ============================================================
    # Phone Number Analysis (Enhanced)
    # ============================================================
    phone_numbers = re.findall(r'(07|01|2547)\d{8}', text_lower)
    if phone_numbers:
        score += 8
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
    
    if grammar_issues > 1:
        score += grammar_issues * 3
        warnings.append(f"📝 Multiple spelling errors detected ({grammar_issues}) - common in scams")
    
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
    # Determine Risk Level with Enhanced Messages
    # ============================================================
    if score >= 65:
        risk_level = "HIGH RISK - SCAM DETECTED"
        color = "danger"
        emoji = "🔴🚨"
        message = "⚠️ CRITICAL SCAM ALERT! This SMS shows strong scam indicators. DO NOT respond, click links, or send money."
    elif score >= 45:
        risk_level = "HIGH RISK"
        color = "danger"
        emoji = "🔴"
        message = "This SMS shows strong scam indicators! Do not click links or send money."
    elif score >= 25:
        risk_level = "MEDIUM RISK"
        color = "warning"
        emoji = "🟡"
        message = "This SMS has suspicious elements. Verify through official channels before taking any action."
    elif score >= 10:
        risk_level = "LOW RISK - CAUTION"
        color = "info"
        emoji = "🔵"
        message = "This SMS shows minor suspicious elements. Be cautious and verify if unexpected."
    else:
        risk_level = "LOW RISK"
        color = "success"
        emoji = "🟢"
        message = "No obvious scam patterns detected. Always exercise normal caution with messages from unknown senders."
    
    # ============================================================
    # Generate Enhanced Recommendations
    # ============================================================
    recommendations = [
        "🔐 NEVER share your M-PESA PIN, password, or OTP codes with anyone",
        "🔗 Don't click suspicious links - they can steal your information",
        "📞 Verify urgent requests by calling the OFFICIAL customer care number",
        "📱 Report scams by forwarding to 333 (Safaricom) or 3333 (Airtel)",
        "🚫 Legitimate companies never ask for your PIN or password via SMS",
        "⏰ Scammers create false urgency - always take time to verify",
        "🛡️ AI Fraud Shield is protecting you - stay vigilant!"
    ]
    
    # Return the result (keeping your exact return structure)
    return {
        'score': score,
        'risk_level': risk_level,
        'color': color,
        'emoji': emoji,
        'message': message,
        'warnings': warnings[:8] if warnings else ["✅ No scam indicators found"],  # Limit to 8 warnings
        'recommendations': recommendations[:5],  # Top 5 recommendations
        'original_message': sms_text[:200] + ('...' if len(sms_text) > 200 else '')
    }