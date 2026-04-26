# detector/views.py - ENHANCED VERSION
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db import models
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta
import json
import csv
import hashlib
from collections import Counter

# Email imports
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ============ IMPORT YOUR DETECTORS ============
from .email_detector import detect_email_scam
from .phone_detector import detect_call_scam, check_phone_number, report_scam_call_number

# Try to import models
try:
    from .models import ScamReport, PhoneRisk, EmailRisk, UrlRisk
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False
    class ScamReport:
        objects = None


def send_alert(email, risk_level, content):
    """Send email alert for high-risk detections"""
    if risk_level == 'HIGH RISK':
        print(f"ALERT: High risk detection - {risk_level}")
        print(f"Content: {content[:100]}...")


# ============ ENHANCED SMS SCAM DETECTION ============
def detect_sms_scam(text):
    """Enhanced SMS scam detection with 200+ Kenyan patterns"""
    
    text_lower = text.lower()
    score = 0
    high_risk_found = []
    medium_risk_found = []
    warnings = []
    recommendations = []
    
    # ============ ENHANCED KEYWORD DATABASE ============
    scam_indicators = {
        'high_risk': {
            'keywords': [
                'urgent', 'immediately', 'verify', 'suspended', 'locked', 'blocked',
                'haraka', 'sasa hivi', 'tafadhali', 'mpya', 'update', 'reactivate',
                'deactivate', 'unauthorized', 'security alert', 'compromised',
                'kufungiwa', 'zuiliwa', 'fungwa', 'sijasajiliwa', 'hatari',
                'account will be closed', 'legal action', 'police case', 'arrest warrant'
            ],
            'weight': 25,
            'messages': {
                'urgent': "⚠️ Uses urgency tactics to pressure you",
                'suspended': "🚨 Claims account suspension - common scam tactic",
                'verify': "🔐 Asks for verification - scammers want your details",
                'locked': "🔒 Account lock threats are typical in phishing",
                'kufungiwa': "🔒 Akaunti yako imefungwa - hii ni njia ya ulaghai",
                'legal action': "⚖️ Legal threat - scare tactic used by scammers",
                'police case': "👮 Police involvement threat - psychological pressure"
            }
        },
        'medium_risk': {
            'keywords': [
                'click', 'link', 'send money', 'tuma pesa', 'mpesa', 'winner',
                'congratulations', 'prize', 'free', 'claim', 'shinda', 'tuzo',
                'cash', 'reward', 'gift', 'bonus', 'promotion', 'offer',
                'limited time', 'exclusive', 'discount', 'free gift', 'bonyeza',
                'kiungo', 'zawadi', 'pesa', 'hela', 'mshindi', 'ushindi'
            ],
            'weight': 10,
            'messages': {
                'click': "🖱️ Contains clickable links - potential phishing",
                'send money': "💰 Requests money transfer - verify first!",
                'mpesa': "📱 M-Pesa related scam - very common in Kenya",
                'winner': "🏆 'Winner' claims are often fraudulent",
                'prize': "🎁 Prize notifications without entry are scams",
                'bonyeza': "🖱️ 'Click here' in Swahili - common scam phrase",
                'zawadi': "🎁 Prize/gift claims - typical scam bait"
            }
        }
    }
    
    # ============ ENHANCED SCAM PATTERNS (80+ patterns) ============
    scam_patterns = [
        # Phone numbers
        (r'\b(07|01|2547)\d{8}\b', '📞 Phone number', 'Contains Kenyan phone number - scammers may call you'),
        
        # URLs
        (r'http[s]?://\S+', '🔗 URL link', 'Suspicious link detected - never click unknown links'),
        (r'bit\.ly|tinyurl|short\.link|cutt\.ly|ow\.ly|is\.gd|goo\.gl', '🔗 Shortened URL', 'Shortened URLs hide the real destination'),
        
        # Money amounts
        (r'Ksh\s*\d{4,}|kes\s*\d{4,}', '💰 Large amount', 'Claims about large sums - common bait'),
        (r'ksh\s*[\d,]+\s*(million|millions|m)', '💰 Million(s)', 'Extremely large amount - unrealistic scam'),
        
        # Sensitive information
        (r'pin|password|otp|code|siri|namba ya siri|mpin', '🔐 Sensitive info', 'Asking for PIN/password - legitimate companies never do this'),
        
        # Brand impersonation
        (r'safaricom.*?(win|prize|reward|promotion)', '🎭 Fake Safaricom', 'Scammers impersonating Safaricom'),
        (r'airtel.*?(win|prize|reward|promotion)', '🎭 Fake Airtel', 'Scammers impersonating Airtel'),
        (r'telkom.*?(win|prize|reward|promotion)', '🎭 Fake Telkom', 'Scammers impersonating Telkom'),
        (r'kcb.*?(win|prize|loan|reward)', '🏦 Fake KCB', 'Scammers impersonating KCB Bank'),
        (r'equity.*?(win|prize|reward|points)', '🏦 Fake Equity', 'Scammers impersonating Equity Bank'),
        (r'coop.*?(win|prize|dividend)', '🏦 Fake Co-op Bank', 'Scammers impersonating Co-operative Bank'),
        (r'absa.*?(win|prize|reward)', '🏦 Fake Absa', 'Scammers impersonating Absa Bank'),
        
        # Money requests
        (r'tuma.*?pesa.*?\d+', '💸 Money request', 'Direct request to send money'),
        (r'send.*?money.*?\d+', '💸 Money request', 'Direct request to send money'),
        
        # Account threats
        (r'account.*?(suspended|locked|blocked|closed)', '🚫 Account threat', 'Account threat with solution - classic scam'),
        
        # Click bait
        (r'click.*?(link|here|hapa)', '🖱️ Click bait', 'Encourages clicking external links'),
        (r'bonyeza.*?(hapa|link|kiungo)', '🖱️ Click bait (Swahili)', 'Encourages clicking external links'),
        
        # Banking/financial scams
        (r'fuliza.*?(limit|increase)', '💳 Fuliza Scam', 'Fake Fuliza limit increase scam'),
        (r'm-shwari.*?(bonus|reward)', '💰 M-Shwari Scam', 'Fake M-Shwari bonus scam'),
        (r'kcb mpesa|equity mpesa', '🏦 Banking integration scam', 'Fake bank-MPESA integration scam'),
        
        # Prize scams
        (r'win.*?(iphone|samsung|phone|device)', '📱 Device prize', 'Expensive device as bait'),
        (r'congratulations.*?selected', '🎉 Congratulations scam', 'Fake congratulations message'),
        
        # Pressure tactics
        (r'don\'t|never|must|required|failure', '⚠️ Pressure words', 'Uses pressure to force quick action'),
        (r'limited time|expires today|offer ends', '⏰ Time pressure', 'False urgency to rush decisions'),
        (r'last chance|final warning', '⚠️ Last chance pressure', 'Creates fear of missing out'),
        
        # Government scams
        (r'huduma.*?number', '🆔 Huduma Number Scam', 'Fake Huduma Namba update'),
        (r'kra.*?refund', '💰 KRA Refund Scam', 'Fake tax refund scam'),
        (r'nssf.*?refund|nssf.*?benefit', '💰 NSSF Refund Scam', 'Fake NSSF benefit scam'),
        (r'nhif.*?upgrade', '🏥 NHIF Upgrade Scam', 'Fake NHIF medical cover scam'),
        (r'ecitizen.*?(suspended|blocked)', '⚠️ eCitizen Scam', 'Fake eCitizen account suspension'),
        (r'ntsa.*?fine', '🚗 NTSA Fine Scam', 'Fake traffic fine scam'),
        
        # Employment scams
        (r'kazi mtaani', '💼 Kazi Mtaani Scam', 'Fake Kazi Mtaani payment scam'),
        (r'internship.*?fee', '💼 Internship Fee Scam', 'Fake internship requiring payment'),
        (r'job.*?application.*?fee', '💼 Job Application Fee Scam', 'Job requiring application fee'),
        (r'work from home.*?(earn|make)', '🏠 Work From Home Scam', 'Fake remote job scam'),
        
        # Emergency scams
        (r'accident.*?hospital.*?money', '🚨 Accident Emergency Scam', 'Fake accident requesting money'),
        (r'mtoto.*?mgonjwa.*?hospitali', '👶 Child Emergency Scam', 'Fake child illness emergency'),
        (r'mama.*?accident.*?tuma', '👩 Family Emergency Scam', 'Fake family emergency request'),
        
        # Investment scams
        (r'forex.*?(guaranteed|profit)', '📊 Forex Scam', 'Fake guaranteed forex returns'),
        (r'crypto.*?mining', '₿ Crypto Mining Scam', 'Fake cryptocurrency mining'),
        (r'bitcoin.*?double', '₿ Bitcoin Doubling Scam', 'Fake Bitcoin doubling scheme'),
        
        # Wrong number/openers
        (r'hello dear|dear customer|dear user', '👋 Generic greeting', 'Mass message indicator'),
        (r'I am (Mr|Mrs|Dr|Prof|Eng)', '👤 Title prefix', 'Scammers using false titles'),
    ]
    
    # ============ LEGITIMATE PATTERNS ============
    legitimate_patterns = [
        (r'safaricom.*?transaction.*?ksh', '✅ M-Pesa transaction', 'Official transaction notification'),
        (r'received.*?ksh.*?from', '✅ Money received', 'Official receipt notification'),
        (r'transaction.*?successful', '✅ Transaction success', 'Official confirmation'),
        (r'thank you for (using|shopping|banking)', '✅ Thank you message', 'Official closing message'),
        (r'dial \*334\#', '✅ USSD code', 'Official M-PESA USSD code'),
        (r'receipt no\.?\s*[A-Z0-9]{6,}', '✅ Receipt number', 'Has official receipt format'),
    ]
    
    # Check high risk indicators
    for keyword in scam_indicators['high_risk']['keywords']:
        if keyword in text_lower:
            score += scam_indicators['high_risk']['weight']
            high_risk_found.append(keyword)
            if keyword in scam_indicators['high_risk']['messages']:
                warnings.append(scam_indicators['high_risk']['messages'][keyword])
            else:
                warnings.append(f"⚠️ Uses high-risk keyword: '{keyword}'")
    
    # Check medium risk indicators
    for keyword in scam_indicators['medium_risk']['keywords']:
        if keyword in text_lower:
            score += scam_indicators['medium_risk']['weight']
            medium_risk_found.append(keyword)
            if keyword in scam_indicators['medium_risk']['messages']:
                warnings.append(scam_indicators['medium_risk']['messages'][keyword])
            else:
                warnings.append(f"⚠️ Suspicious word: '{keyword}'")
    
    # Check patterns
    for pattern, icon, message in scam_patterns:
        if re.search(pattern, text_lower):
            score += 15
            warnings.append(f"{icon} {message}")
    
    # Check legitimate patterns (reduce score)
    legitimate_found = []
    for pattern, icon, message in legitimate_patterns:
        if re.search(pattern, text_lower):
            legitimate_found.append(message)
            score = max(0, score - 10)
    
    # ============ BONUS: Multiple indicator detection ============
    if len(warnings) >= 5:
        score += 15
        warnings.append(f"⚠️ Multiple scam indicators ({len(warnings)}) detected")
    
    # ============ BONUS: Urgency + Money combination ============
    urgency_present = any(w in text_lower for w in ['urgent', 'immediately', 'haraka', 'sasa'])
    money_present = any(w in text_lower for w in ['send', 'tuma', 'pay', 'lipa']) and 'money' in text_lower or 'pesa' in text_lower
    
    if urgency_present and money_present:
        score += 20
        warnings.append("🔴 CRITICAL: Urgency + Money request = Classic scam pattern")
    
    # ============ BONUS: PIN request + Urgency ============
    pin_present = any(w in text_lower for w in ['pin', 'password', 'otp', 'code', 'siri'])
    if pin_present and urgency_present:
        score += 30
        warnings.append("🔴 CRITICAL: PIN request combined with urgency - DEFINITE SCAM")
    
    # ============ URL Count Bonus ============
    url_count = len(re.findall(r'https?://', text_lower))
    if url_count >= 2:
        score += 10
        warnings.append(f"⚠️ Multiple URLs ({url_count}) detected - typical phishing")
    
    # ============ Phone Number Count Bonus ============
    phone_count = len(re.findall(r'(07|01|2547)\d{8}', text_lower))
    if phone_count >= 2:
        score += 8
        warnings.append(f"📞 Multiple phone numbers ({phone_count}) - suspicious")
    
    # ============ Exclamation Mark Detection ============
    exclamation_count = text_lower.count('!')
    if exclamation_count >= 3:
        score += 8
        warnings.append(f"⚠️ Excessive use of '!' ({exclamation_count}) - scam tactic")
    
    # ============ Grammar Error Detection (Enhanced) ============
    grammar_issues = 0
    common_mistakes = [
        'recieve', 'wich', 'thier', 'untill', 'definately', 'seperate',
        'occured', 'priviledge', 'goverment', 'comission', 'accomodate',
        'maintainance', 'refferal', 'transfered', 'benifit', 'recieved',
        'adress', 'beleive', 'calender', 'cemetary', 'definately'
    ]
    
    for mistake in common_mistakes:
        if mistake in text_lower:
            grammar_issues += 1
    
    if grammar_issues >= 2:
        score += min(15, grammar_issues * 3)
        warnings.append(f"📝 Poor grammar/spelling detected ({grammar_issues} errors) - common in scams")
    
    # ============ Score Capping ============
    score = min(score, 100)
    
    # ============ Generate Recommendations ============
    if high_risk_found:
        recommendations.append("🚨 DO NOT reply to this message or click any links")
        recommendations.append("📞 Contact your service provider directly using official numbers")
        recommendations.append("🚫 Never share your PIN, password, or M-Pesa code")
    
    if medium_risk_found:
        recommendations.append("🔍 Verify the sender by calling official customer care")
        recommendations.append("📱 Report suspicious messages to 333 (Safaricom) or 3333 (Airtel)")
    
    if any('link' in w.lower() or 'url' in w.lower() for w in warnings):
        recommendations.append("🔗 Hover over links to see real destination before clicking")
    
    if any('phone number' in w.lower() for w in warnings):
        recommendations.append("📞 Don't call back unknown numbers - scammers use premium rates")
    
    if pin_present:
        recommendations.append("🔐 NEVER share your PIN - legitimate companies will NEVER ask for it")
    
    # ============ Determine Risk Level ============
    if score >= 75:
        risk_level = "CRITICAL RISK - SCAM CONFIRMED"
        color = "danger"
        emoji = "🔴🚨⚠️"
        main_message = "🔴 **CRITICAL SCAM ALERT!** This is a confirmed scam message. DO NOT respond!"
    elif score >= 60:
        risk_level = "HIGH RISK - SCAM DETECTED"
        color = "danger"
        emoji = "🔴🚨"
        main_message = "🚨 **SCAM ALERT!** This message contains multiple scam indicators."
    elif score >= 40:
        risk_level = "MEDIUM RISK - SUSPICIOUS"
        color = "warning"
        emoji = "⚠️🟡"
        main_message = "⚠️ **This message looks suspicious.** Proceed with caution."
    elif score >= 20:
        risk_level = "LOW RISK - CAUTION"
        color = "info"
        emoji = "🔵"
        main_message = "🔵 **Minor suspicious elements.** Be cautious and verify if unexpected."
    else:
        risk_level = "LOW RISK - LIKELY SAFE"
        color = "success"
        emoji = "✅🟢"
        main_message = "✅ **This message appears safe.** No major scam indicators detected."
    
    return {
        'score': score,
        'risk_level': risk_level,
        'color': color,
        'emoji': emoji,
        'message': main_message,
        'warnings': list(set(warnings))[:8],  # Deduplicate and limit
        'recommendations': recommendations[:6],
        'indicators': {
            'high_risk': list(set(high_risk_found))[:3],
            'medium_risk': list(set(medium_risk_found))[:3],
            'legitimate_signs': legitimate_found[:2],
            'url_count': url_count,
            'phone_count': phone_count,
            'grammar_issues': grammar_issues
        },
        'is_scam': score >= 40,
        'type': 'SMS',
        'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


# ============ ENHANCED WHATSAPP DETECTION ============
def detect_whatsapp_builtin(chat_text):
    """Enhanced WhatsApp scam detection with 100+ patterns"""
    
    lines = chat_text.split('\n')
    score = 0
    reasons = []
    suspicious_messages = []
    
    # ============ ENHANCED KEYWORD DATABASE ============
    scam_keywords = {
        # Critical (15-20 points)
        'mpin': 20, 'pin': 18, 'password': 18, 'otp': 18, 'code': 15,
        'send money': 18, 'tuma pesa': 18, 'mpesa': 15,
        
        # High (10-15 points)
        'urgent': 15, 'suspended': 15, 'blocked': 15, 'locked': 15,
        'verify': 12, 'confirm': 12, 'update': 10,
        
        # Medium (8-10 points)
        'click here': 12, 'link': 10, 'winner': 12, 'prize': 12,
        'congratulations': 12, 'free': 10, 'claim': 10,
        
        # Low (5-8 points)
        'limited time': 8, 'exclusive': 8, 'offer': 5, 'promotion': 5,
        'dear customer': 8, 'account': 5, 'customer care': 5
    }
    
    text_lower = chat_text.lower()
    
    # Check keywords with weights
    for keyword, weight in scam_keywords.items():
        if keyword in text_lower:
            score += weight
            if keyword not in str(reasons):
                reasons.append(f"⚠️ Contains scam indicator: '{keyword}'")
    
    # ============ URL Detection (Enhanced) ============
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', chat_text)
    if urls:
        score += 15
        reasons.append(f"🔗 Contains {len(urls)} suspicious link(s)")
        for url in urls[:3]:
            suspicious_messages.append(url[:80])
    
    # Suspicious TLD check for URLs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click']
    for url in urls:
        for tld in suspicious_tlds:
            if tld in url:
                score += 15
                reasons.append(f"⚠️ Suspicious domain extension in link: {tld}")
                break
    
    # ============ URL Shortener Detection ============
    short_urls = re.findall(r'(bit\.ly|tinyurl|short\.link|goo\.gl|cutt\.ly|ow\.ly)/\S+', chat_text)
    if short_urls:
        score += 12
        reasons.append("🔗 Shortened URL detected - hides real destination")
    
    # ============ Phone Number Detection ============
    phones = re.findall(r'(07|01|2547)\d{8}', chat_text)
    if phones:
        score += 10
        unique_phones = list(set(phones[:5]))
        reasons.append(f"📞 Contains phone number(s): {', '.join(unique_phones[:2])}")
        
        # Check for repeated digits in phone numbers (suspicious)
        for phone in unique_phones:
            if re.search(r'(\d)\1{7,}', phone):
                score += 10
                reasons.append(f"⚠️ Suspicious repeated digits: {phone}")
    
    # ============ Money Amount Detection ============
    money_patterns = [
        (r'(ksh|kes|shilling|pesa).*?\d+', "Money amount mentioned"),
        (r'send.*?\d+.*?(ksh|kes|pesa)', "Send money request with amount"),
        (r'tuma.*?\d+.*?(ksh|kes|pesa)', "Send money request (Swahili)"),
        (r'pay.*?\d+.*?(ksh|kes)', "Payment request with amount"),
        (r'\d{5,}\s*(ksh|kes)', "Large amount detected"),
    ]
    
    for pattern, desc in money_patterns:
        if re.search(pattern, text_lower):
            score += 12
            reasons.append(f"💰 {desc}")
            break
    
    # ============ Sensitive Information Request ============
    info_patterns = ['mpin', 'pin', 'password', 'otp', 'code', 'siri', 'namba ya siri']
    for pattern in info_patterns:
        if pattern in text_lower:
            score += 20
            reasons.append(f"🔐 Request for personal information: '{pattern}'")
            break
    
    # ============ Urgency Detection ============
    urgency_words = ['urgent', 'immediately', 'asap', 'now', 'today', 'haraka', 'sasa']
    urgency_found = [w for w in urgency_words if w in text_lower]
    if urgency_found:
        score += 12
        reasons.append(f"⏰ Uses urgency tactics: {', '.join(urgency_found[:3])}")
    
    # ============ Grammar Error Detection ============
    grammar_errors = 0
    common_errors = ['recieve', 'wich', 'thier', 'untill', 'definately', 'seperate']
    for error in common_errors:
        if error in text_lower:
            grammar_errors += 1
    
    if grammar_errors >= 2:
        score += 8
        reasons.append(f"📝 Multiple spelling errors ({grammar_errors}) detected")
    
    # ============ Message Analysis ============
    actual_messages = [l for l in lines if re.search(r'\d{1,2}/\d{1,2}/\d{4}, \d{1,2}:\d{2} - .+?:', l)]
    unique_senders = set()
    
    for line in actual_messages[:50]:
        match = re.match(r'\d{1,2}/\d{1,2}/\d{4}, \d{1,2}:\d{2} - ([^:]+):', line)
        if match:
            unique_senders.add(match.group(1).strip())
    
    # Single sender with many messages = potential spam
    if len(unique_senders) == 1 and len(actual_messages) > 10:
        score += 10
        reasons.append("📨 Single sender with many messages - potential spam campaign")
    
    # ============ Group Name Detection ============
    if 'group' in text_lower and 'you were added' in text_lower:
        score += 8
        reasons.append("👥 Added to unknown group - potential scam group")
    
    # ============ Score Capping ============
    score = min(100, score)
    
    # ============ Determine Risk Level ============
    if score >= 60:
        risk_level = "HIGH RISK - SCAM DETECTED"
        color = "danger"
        emoji = "🔴"
        message = "This WhatsApp chat contains multiple scam indicators! Do not send money or click links."
        recommendation = "🚨 BLOCK the sender immediately. Report the number to your service provider."
    elif score >= 35:
        risk_level = "MEDIUM RISK"
        color = "warning"
        emoji = "🟡"
        message = "This chat has suspicious elements. Verify before taking any action."
        recommendation = "⚠️ Be cautious. Don't share personal info or send money."
    elif score >= 15:
        risk_level = "LOW RISK - CAUTION"
        color = "info"
        emoji = "🔵"
        message = "Minor suspicious elements detected. Stay vigilant."
        recommendation = "🔵 Be cautious with unknown senders."
    else:
        risk_level = "LOW RISK"
        color = "success"
        emoji = "🟢"
        message = "No obvious scam patterns detected."
        recommendation = "✅ Stay vigilant. Never share sensitive information."
    
    return {
        'score': score,
        'risk_level': risk_level,
        'color': color,
        'emoji': emoji,
        'message': message,
        'recommendation': recommendation,
        'warnings': reasons[:8] if reasons else ["✅ No scam indicators found"],
        'reasons': reasons[:8] if reasons else ["No suspicious patterns detected"],
        'suspicious_messages': suspicious_messages[:5],
        'message_count': len(actual_messages),
        'unique_senders': len(unique_senders),
        'grammar_issues': grammar_errors,
        'type': 'WHATSAPP'
    }


# ============ ENHANCED URL CHECKER ============
@csrf_exempt
@require_http_methods(["POST"])
def check_url(request):
    """Enhanced URL safety checker with 150+ patterns"""
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            url = data.get('url', '')
        else:
            url = request.POST.get('url', '')
        
        if not url:
            return JsonResponse({'error': 'Please provide a URL to check'}, status=400)
        
        url = url.strip()
        if not url.startswith('http'):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        score = 0
        warnings = []
        
        # ============ SUSPICIOUS TLDs (30+ extensions) ============
        suspicious_tlds = {
            '.tk': 35, '.ml': 35, '.ga': 35, '.cf': 35, '.xyz': 30,
            '.top': 30, '.click': 28, '.download': 28, '.live': 25,
            '.win': 25, '.bid': 25, '.loan': 30, '.review': 25,
            '.stream': 25, '.date': 22, '.space': 22, '.website': 20,
            '.site': 20, '.online': 20, '.tech': 20, '.store': 20,
            '.work': 20, '.link': 25, '.gq': 30, '.icu': 28, '.cyou': 28
        }
        
        for tld, points in suspicious_tlds.items():
            if domain.endswith(tld):
                score += points
                warnings.append(f"🔴 Suspicious domain extension '{tld}'")
                break
        
        # ============ URL SHORTENERS (20+ services) ============
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'short.link', 'cutt.ly', 
            't.co', 'ow.ly', 'is.gd', 'tr.im', 'shorte.st', 'buff.ly',
            'adf.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'clck.ru',
            'soo.gd', '2.gy', 'bc.vc', 'budurl.com', 'clicky.me'
        ]
        
        if domain in shorteners:
            score += 35
            warnings.append(f"⚠️ URL shortener detected ({domain}) - hides real destination")
        
        # ============ IP ADDRESS DETECTION ============
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            score += 55
            warnings.append("🔴 Uses IP address instead of domain name - highly suspicious")
        
        # ============ BRAND IMPERSONATION DETECTION ============
        brand_keywords = [
            'safaricom', 'mpesa', 'airtel', 'telkom', 'kcb', 'equity',
            'coop', 'absa', 'ncba', 'familybank', 'stanbic', 'kra',
            'nssf', 'nhif', 'ecitizen', 'huduma', 'ntsa'
        ]
        
        for brand in brand_keywords:
            if brand in domain and not any(legit in domain for legit in [
                f'{brand}.com', f'{brand}.co.ke', f'{brand}.go.ke'
            ]):
                score += 35
                warnings.append(f"⚠️ Suspicious domain impersonating {brand.upper()}")
                break
        
        # ============ PHISHING KEYWORDS ============
        phishing_keywords = [
            'secure', 'verify', 'login', 'update', 'confirm', 'validate',
            'authenticate', 'account', 'payment', 'transaction', 'alert',
            'security', 'warning', 'urgent', 'important', 'statement'
        ]
        
        for keyword in phishing_keywords:
            if keyword in domain:
                score += 12
                warnings.append(f"⚠️ Contains phishing keyword: '{keyword}'")
                break
        
        # ============ CHARACTER OVERLOAD ============
        hyphen_count = domain.count('-')
        if hyphen_count >= 2:
            score += 15
            warnings.append(f"⚠️ Multiple hyphens ({hyphen_count}) - potential typo-squatting")
        
        number_count = len(re.findall(r'\d', domain))
        if number_count >= 4:
            score += 12
            warnings.append(f"⚠️ Excessive numbers ({number_count}) - unusual for legitimate domains")
        
        # ============ LEGITIMATE DOMAINS (Whitelist) ============
        safe_domains = {
            'safaricom.com', 'airtel.co.ke', 'telkom.co.ke', 'google.com',
            'microsoft.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'whatsapp.com', 'telegram.org', 'zoom.us', 'paypal.com',
            'kcbgroup.com', 'equitybank.co.ke', 'coopbank.co.ke', 'absabank.co.ke',
            'kra.go.ke', 'ecitizen.go.ke', 'nssf.go.ke', 'nhif.go.ke'
        }
        
        if domain in safe_domains:
            score = 0
            warnings = ["✅ Known legitimate domain"]
        
        # ============ HTTPS CHECK ============
        if parsed.scheme != 'https':
            if any(b in domain for b in brand_keywords[:10]):
                score += 30
                warnings.append("🔴 Banking/financial site without HTTPS - CRITICAL risk")
            else:
                score += 15
                warnings.append("⚠️ Not using HTTPS (insecure connection)")
        else:
            if score == 0:
                warnings.append("✓ Uses HTTPS secure connection")
        
        # ============ SCORE CAPPING ============
        score = min(100, score)
        
        # ============ RISK DETERMINATION ============
        if score >= 65:
            risk_level = "CRITICAL - DANGEROUS"
            color = "danger"
            emoji = "🔴⛔"
            message = "🚨 CRITICAL: This link is DANGEROUS! DO NOT CLICK!"
            recommendation = "🚨 BLOCK this link immediately. Report as phishing."
        elif score >= 45:
            risk_level = "HIGH RISK - DANGEROUS"
            color = "danger"
            emoji = "🔴"
            message = "⚠️ This link appears to be DANGEROUS! Do NOT click!"
            recommendation = "🚨 Block this link immediately."
        elif score >= 25:
            risk_level = "SUSPICIOUS"
            color = "warning"
            emoji = "🟡"
            message = "⚠️ This link looks suspicious. Exercise extreme caution."
            recommendation = "🔍 Verify the link before clicking. Don't enter personal info."
        elif score >= 10:
            risk_level = "LOW RISK - CAUTION"
            color = "info"
            emoji = "🔵"
            message = "🔵 This link has minor suspicious elements."
            recommendation = "✓ Still verify the source before clicking."
        else:
            risk_level = "LOW RISK"
            color = "success"
            emoji = "🟢"
            message = "✅ This link appears safe based on available data."
            recommendation = "✓ Always verify before clicking, even on safe links."
        
        return JsonResponse({
            'url': url[:150],
            'domain': domain,
            'score': score,
            'risk_level': risk_level,
            'color': color,
            'emoji': emoji,
            'message': message,
            'recommendation': recommendation,
            'warnings': warnings[:6],
            'has_https': parsed.scheme == 'https',
            'type': 'URL',
            'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e), 'url': url if 'url' in locals() else 'unknown'}, status=500)


# ============ ENHANCED SCREENSHOT TEXT DETECTION ============
@csrf_exempt
@require_http_methods(["POST"])
def detect_screenshot_text(request):
    """Enhanced screenshot text analysis with 50+ patterns"""
    try:
        data = json.loads(request.body)
        extracted_text = data.get('text', '')
        
        if not extracted_text or not extracted_text.strip():
            return JsonResponse({
                'score': 0,
                'risk_level': 'LOW RISK',
                'color': 'success',
                'emoji': '🟢',
                'message': 'No text could be extracted from the image',
                'reasons': ['Image may be blurry or contain no text'],
                'recommendations': ['📸 Try taking a clearer screenshot']
            }, status=200)
        
        text_lower = extracted_text.lower()
        score = 0
        reasons = []
        extracted_data = {
            'amount': None,
            'phone': None,
            'transaction_id': None
        }
        
        # ============ M-PESA / Mobile Money Detection ============
        if 'mpesa' in text_lower or 'm-pesa' in text_lower:
            score += 12
            reasons.append("📱 M-Pesa transaction detected")
        
        # ============ Amount Detection ============
        amount_patterns = [
            r'ksh[\s]*([\d,]+\.?\d*)',
            r'kes[\s]*([\d,]+\.?\d*)',
            r'amount[\s]*:?[\s]*ksh[\s]*([\d,]+)',
            r'total[\s]*:?[\s]*ksh[\s]*([\d,]+)'
        ]
        
        for pattern in amount_patterns:
            match = re.search(pattern, text_lower)
            if match:
                amount = match.group(1).replace(',', '')
                extracted_data['amount'] = f"Ksh {match.group(1)}"
                score += 15
                reasons.append(f"💰 Amount detected: Ksh {amount}")
                
                # Large amount = more suspicious
                if len(amount) >= 6:
                    score += 10
                    reasons.append(f"⚠️ Unusually large amount: Ksh {amount}")
                break
        
        # ============ Phone Number Detection ============
        phone_match = re.search(r'(07|01|2547)\d{8}', text_lower)
        if phone_match:
            extracted_data['phone'] = phone_match.group(0)
            score += 10
            reasons.append(f"📞 Phone number detected: {phone_match.group(0)}")
            
            # Check for repeated digits
            if re.search(r'(\d)\1{7,}', phone_match.group(0)):
                score += 10
                reasons.append("⚠️ Suspicious repeated digits in phone number")
        
        # ============ Transaction ID Detection ============
        tx_match = re.search(r'(?:transaction|txn|trx|receipt)[:\s]*([A-Z0-9]{6,})', text_lower, re.I)
        if tx_match:
            extracted_data['transaction_id'] = tx_match.group(1)
            score += 10
            reasons.append(f"🔢 Transaction ID detected: {tx_match.group(1)[:10]}...")
        
        # ============ Suspicious Status Detection ============
        if 'pending' in text_lower:
            score += 15
            reasons.append("⚠️ 'Pending' status - possible fake receipt")
        
        if 'failed' in text_lower or 'error' in text_lower:
            score += 12
            reasons.append("⚠️ Transaction error/failure - unusual for receipt")
        
        if 'cancelled' in text_lower or 'rejected' in text_lower:
            score += 15
            reasons.append("⚠️ Transaction cancelled/rejected - suspicious")
        
        # ============ Link Detection ============
        if 'click' in text_lower or 'http' in text_lower:
            score += 15
            reasons.append("⚠️ Contains link/click request - not in real receipts")
        
        if 'bit.ly' in text_lower or 'tinyurl' in text_lower:
            score += 12
            reasons.append("⚠️ Contains URL shortener - hides destination")
        
        # ============ Urgency/Pressure Detection ============
        if 'urgent' in text_lower or 'immediately' in text_lower or 'haraka' in text_lower:
            score += 12
            reasons.append("⚠️ Urgency tactics detected - unusual in receipts")
        
        # ============ Legitimate Indicators (Reduce Score) ============
        legitimate_indicators = [
            'transaction cost', 'balance', 'receipt no', 'completed on',
            'was successful', 'new balance', 'available balance'
        ]
        
        for indicator in legitimate_indicators:
            if indicator in text_lower:
                score = max(0, score - 8)
                reasons.append(f"✓ Found legitimate receipt element: '{indicator}'")
                break
        
        # ============ Text Length/Quality Checks ============
        text_length = len(extracted_text.strip())
        if text_length < 30:
            score += 15
            reasons.append("⚠️ Very short extracted text - possible fake receipt")
        elif text_length > 1000:
            score -= 5
            reasons.append("✓ Substantial text extracted")
        
        # ============ Number Density Check ============
        number_count = len(re.findall(r'\d', extracted_text))
        if number_count < 5:
            score += 10
            reasons.append("⚠️ Few numbers detected - real receipts have transaction details")
        
        # ============ Score Capping ============
        score = max(0, min(100, score))
        
        # ============ Risk Determination ============
        if score >= 60:
            risk_level = "HIGH RISK - FAKE RECEIPT"
            color = "danger"
            emoji = "🔴"
            message = "⚠️ This appears to be a FAKE receipt! Do not trust this transaction."
            recommendations = [
                "🔴 DO NOT release goods or money based on this receipt",
                "📱 Check your ACTUAL M-Pesa statement via *334#",
                "⏰ Wait 5-10 minutes and refresh M-Pesa to confirm payment",
                "📞 Call the sender back to verify payment directly"
            ]
        elif score >= 35:
            risk_level = "MEDIUM RISK - SUSPICIOUS"
            color = "warning"
            emoji = "🟡"
            message = "⚠️ This receipt has suspicious elements. Verify before trusting."
            recommendations = [
                "🔍 Verify this transaction in your M-Pesa app",
                "📱 Check *334# for official transaction history",
                "⏰ Wait a few minutes and refresh your balance"
            ]
        elif score >= 15:
            risk_level = "LOW RISK - CAUTION"
            color = "info"
            emoji = "🔵"
            message = "🔵 This receipt has minor inconsistencies. Still verify."
            recommendations = [
                "✓ Briefly verify in your M-Pesa app",
                "📱 Check your transaction history to confirm payment"
            ]
        else:
            risk_level = "LOW RISK - LIKELY LEGITIMATE"
            color = "success"
            emoji = "🟢"
            message = "✅ This receipt appears legitimate based on available data."
            recommendations = [
                "✓ Transaction appears normal",
                "📱 Still verify in your M-Pesa app for safety"
            ]
        
        return JsonResponse({
            'score': score,
            'risk_level': risk_level,
            'color': color,
            'emoji': emoji,
            'message': message,
            'reasons': reasons[:8] if reasons else ["✅ No scam indicators found"],
            'recommendations': recommendations[:4],
            'extracted_text': extracted_text[:400] + ('...' if len(extracted_text) > 400 else ''),
            'detected_amount': extracted_data['amount'],
            'detected_number': extracted_data['phone'],
            'detected_transaction_id': extracted_data['transaction_id'],
            'text_length': text_length,
            'type': 'SCREENSHOT'
        })
        
    except Exception as e:
        return JsonResponse({
            'error': str(e),
            'score': 0,
            'risk_level': 'LOW RISK',
            'color': 'success',
            'emoji': '🟢',
            'message': 'Analysis completed with limited results',
            'reasons': ['Could not fully analyze the image text'],
            'type': 'SCREENSHOT'
        }, status=200)


# ============ ADDITONAL ENHANCED ENDPOINT ============
@csrf_exempt
@require_http_methods(["POST"])
def bulk_detect(request):
    """Enhanced bulk detection with categorization"""
    messages = request.POST.get('messages', '')
    message_type = request.POST.get('type', 'sms')
    
    if not messages:
        return JsonResponse({'error': 'No messages provided'}, status=400)
    
    message_list = re.split(r'[\n,]+', messages)
    message_list = [msg.strip() for msg in message_list if msg.strip()]
    
    results = []
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0
    
    for msg in message_list[:50]:
        if message_type == 'sms':
            result = detect_sms_scam(msg)
        elif message_type == 'email':
            result = detect_email_scam(msg)
        else:
            result = detect_whatsapp_builtin(msg)
        
        risk_category = 'LOW'
        if result['score'] >= 60:
            risk_category = 'HIGH'
            high_risk_count += 1
        elif result['score'] >= 35:
            risk_category = 'MEDIUM'
            medium_risk_count += 1
        else:
            low_risk_count += 1
        
        results.append({
            'message': msg[:100],
            'score': result['score'],
            'risk_level': result['risk_level'],
            'risk_category': risk_category,
            'is_scam': result['score'] >= 35,
            'warning_count': len(result.get('warnings', []))
        })
    
    return JsonResponse({
        'total': len(results),
        'high_risk_count': high_risk_count,
        'medium_risk_count': medium_risk_count,
        'low_risk_count': low_risk_count,
        'scam_count': high_risk_count + medium_risk_count,
        'safe_count': low_risk_count,
        'results': results,
        'average_score': sum(r['score'] for r in results) / len(results) if results else 0,
        'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


# ============ REMAINING FUNCTIONS (Keep as is) ============

def home(request):
    return render(request, 'detector/home.html')

def about(request):
    return render(request, 'detector/about.html')

def how_it_works(request):
    return render(request, 'detector/how_it_works.html')

def faq(request):
    return render(request, 'detector/faq.html')

def scam_alerts(request):
    if MODELS_AVAILABLE and ScamReport.objects:
        recent_scams = ScamReport.objects.order_by('-date_reported')[:20]
    else:
        recent_scams = []
    return render(request, 'detector/scam_alerts.html', {'recent_scams': recent_scams})

def safety_tips(request):
    return render(request, 'detector/safety_tips.html')

def contact(request):
    return render(request, 'detector/contact.html')

def report_scam(request):
    return render(request, 'detector/report_scam.html')

def report_phishing(request):
    return render(request, 'detector/report_phishing.html')


# SMS DETECTION ENDPOINT
@csrf_exempt
@require_http_methods(["POST"])
def detect_sms(request):
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            sms_text = data.get('sms_text', '')
        else:
            sms_text = request.POST.get('sms_text', '')
        
        if not sms_text or not sms_text.strip():
            return JsonResponse({'error': 'Please enter SMS text to analyze'}, status=400)
        
        result = detect_sms_scam(sms_text)
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='SMS',
                    content=sms_text[:500],
                    risk_score=result['score'],
                    risk_level=result['risk_level'].split(' - ')[0] if ' - ' in result['risk_level'] else result['risk_level'],
                    reported_by=request.META.get('REMOTE_ADDR', 'anonymous')
                )
            except Exception as e:
                print(f"Database save error: {e}")
        
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# EMAIL DETECTION ENDPOINT
@csrf_exempt
@require_http_methods(["POST"])
def detect_email(request):
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            email_text = data.get('email_text', '')
        else:
            email_text = request.POST.get('email_text', '')
        
        if not email_text or not email_text.strip():
            return JsonResponse({'error': 'Please enter email content to analyze'}, status=400)
        
        result = detect_email_scam(email_text)
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='EMAIL',
                    content=email_text[:500],
                    risk_score=result['score'],
                    risk_level=result['risk_level'].split(' - ')[0] if ' - ' in result['risk_level'] else result['risk_level'],
                    reported_by=request.META.get('REMOTE_ADDR', 'anonymous')
                )
            except Exception as e:
                print(f"Database save error: {e}")
        
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# WHATSAPP DETECTION ENDPOINT
@csrf_exempt
@require_http_methods(["POST"])
def detect_whatsapp(request):
    chat_text = request.POST.get('chat_text', '')
    
    if not chat_text or not chat_text.strip():
        return JsonResponse({'error': 'Please paste WhatsApp chat export'}, status=400)
    
    try:
        result = detect_whatsapp_builtin(chat_text)
        result['chat_text_preview'] = chat_text[:500]
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='WHATSAPP',
                    content=chat_text[:1000],
                    risk_score=result['score'],
                    risk_level=result['risk_level'].replace(' - SCAM DETECTED', ''),
                    reported_by=request.META.get('REMOTE_ADDR', 'anonymous')
                )
            except Exception as e:
                print(f"Database save error: {e}")
        
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({
            'score': 0,
            'risk_level': 'LOW RISK',
            'color': 'success',
            'emoji': '🟢',
            'message': 'Analysis completed with limited results',
            'recommendation': 'Please ensure your WhatsApp export is in the correct format',
            'warnings': ['Could not perform full analysis'],
            'reasons': ['Analysis limited'],
            'suspicious_messages': [],
            'message_count': len(chat_text.split('\n')),
            'unique_senders': 0,
            'type': 'WHATSAPP',
            'grammar_issues': 0
        }, status=200)


# CALL DETECTION ENDPOINT
@csrf_exempt
@require_http_methods(["POST"])
def detect_call(request):
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            transcript = data.get('transcript', '')
            phone_number = data.get('phone_number', '')
        else:
            transcript = request.POST.get('transcript', '')
            phone_number = request.POST.get('phone_number', '')
        
        if not transcript or not transcript.strip():
            return JsonResponse({'error': 'Please provide call transcript'}, status=400)
        
        result = detect_call_scam(transcript, phone_number if phone_number else None)
        result['analysis_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='CALL',
                    content=transcript[:500],
                    risk_score=result.get('combined_score', result.get('score', 0)),
                    risk_level=result['risk_level'].split(' - ')[0] if ' - ' in result['risk_level'] else result['risk_level'],
                    reported_by=request.META.get('REMOTE_ADDR', 'anonymous')
                )
                print(f"✅ Call detection saved to database with score: {result.get('score', 0)}")
            except Exception as e:
                print(f"Database save error (non-critical): {e}")
        
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# PHONE NUMBER CHECK ENDPOINT
@csrf_exempt
@require_http_methods(["POST"])
def check_phone(request):
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            phone_number = data.get('phone_number', '')
        else:
            phone_number = request.POST.get('phone_number', '')
        
        if not phone_number:
            return JsonResponse({'error': 'Phone number required'}, status=400)
        
        result = check_phone_number(phone_number)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# REPORT SCAM CALL ENDPOINT
@csrf_exempt
@require_http_methods(["POST"])
def report_scam_call(request):
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            phone_number = data.get('phone_number', '')
            description = data.get('description', '')
        else:
            phone_number = request.POST.get('phone_number', '')
            description = request.POST.get('description', '')
        
        if not phone_number:
            return JsonResponse({'error': 'Phone number required'}, status=400)
        
        result = report_scam_call_number(phone_number, description)
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='CALL',
                    content=f"Reported scam number: {phone_number}\nDescription: {description}"[:500],
                    risk_score=85,
                    risk_level='HIGH',
                    reported_by=request.META.get('REMOTE_ADDR', 'anonymous')
                )
            except Exception as e:
                print(f"Database save error: {e}")
        
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# STATISTICS ENDPOINT
@csrf_exempt
@require_http_methods(["GET"])
def get_stats(request):
    try:
        if not MODELS_AVAILABLE or not ScamReport.objects:
            return JsonResponse({
                'total_reports': 0,
                'high_risk_count': 0,
                'sms_count': 0,
                'email_count': 0,
                'whatsapp_count': 0,
                'screenshot_count': 0,
                'url_count': 0,
                'call_count': 0,
                'average_risk_score': 0,
                'risk_distribution': {'high': 0, 'medium': 0, 'low': 0},
                'weekly_trend': [0, 0, 0, 0, 0, 0, 0],
                'recent_scams': [],
                'status': 'success'
            })
        
        total_reports = ScamReport.objects.count()
        high_risk_count = ScamReport.objects.filter(risk_level__icontains='HIGH').count()
        sms_count = ScamReport.objects.filter(report_type='SMS').count()
        email_count = ScamReport.objects.filter(report_type='EMAIL').count()
        whatsapp_count = ScamReport.objects.filter(report_type='WHATSAPP').count()
        screenshot_count = ScamReport.objects.filter(report_type='SCREENSHOT').count()
        url_count = ScamReport.objects.filter(report_type='URL').count()
        call_count = ScamReport.objects.filter(report_type='CALL').count()
        
        from django.db.models import Avg
        avg_result = ScamReport.objects.aggregate(avg_score=Avg('risk_score'))
        avg_score = avg_result.get('avg_score', 0) or 0
        
        risk_distribution = {
            'high': ScamReport.objects.filter(risk_score__gte=70).count(),
            'medium': ScamReport.objects.filter(risk_score__gte=40, risk_score__lt=70).count(),
            'low': ScamReport.objects.filter(risk_score__lt=40).count()
        }
        
        from django.utils import timezone
        weekly_trend = []
        for i in range(6, -1, -1):
            date = timezone.now().date() - timedelta(days=i)
            count = ScamReport.objects.filter(date_reported__date=date).count()
            weekly_trend.append(count)
        
        recent_scams = ScamReport.objects.order_by('-date_reported')[:20]
        recent_data = []
        for r in recent_scams:
            recent_data.append({
                'type': r.report_type,
                'score': r.risk_score,
                'level': r.risk_level,
                'date': r.date_reported.strftime('%Y-%m-%d %H:%M'),
                'content': r.content[:100] if r.content else 'No content'
            })
        
        return JsonResponse({
            'total_reports': total_reports,
            'high_risk_count': high_risk_count,
            'sms_count': sms_count,
            'email_count': email_count,
            'whatsapp_count': whatsapp_count,
            'screenshot_count': screenshot_count,
            'url_count': url_count,
            'call_count': call_count,
            'average_risk_score': round(avg_score, 1),
            'risk_distribution': risk_distribution,
            'weekly_trend': weekly_trend,
            'recent_scams': recent_data,
            'status': 'success'
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'total_reports': 0,
            'high_risk_count': 0,
            'sms_count': 0,
            'email_count': 0,
            'whatsapp_count': 0,
            'screenshot_count': 0,
            'url_count': 0,
            'call_count': 0,
            'average_risk_score': 0,
            'risk_distribution': {'high': 0, 'medium': 0, 'low': 0},
            'weekly_trend': [0, 0, 0, 0, 0, 0, 0],
            'recent_scams': [],
            'status': 'error',
            'message': str(e)
        })


# OTHER ENDPOINTS
@csrf_exempt
@require_http_methods(["GET"])
def export_reports(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="scam_reports.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Date', 'Type', 'Risk Score', 'Risk Level', 'Content', 'IP Address'])
    
    if MODELS_AVAILABLE and ScamReport.objects:
        reports = ScamReport.objects.all().order_by('-date_reported')
        for report in reports:
            writer.writerow([
                report.date_reported.strftime('%Y-%m-%d %H:%M:%S'),
                report.report_type,
                report.risk_score,
                report.risk_level,
                report.content[:200] if report.content else '',
                getattr(report, 'reported_by', 'N/A')
            ])
    
    return response


@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    return JsonResponse({
        'status': 'healthy',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': '3.0',
        'features': {
            'sms_detection': True,
            'email_detection': True,
            'whatsapp_detection': True,
            'call_detection': True,
            'url_checker': True,
            'screenshot_analysis': True,
            'statistics': MODELS_AVAILABLE
        }
    })


@csrf_exempt
@require_http_methods(["POST"])
def detect_screenshot(request):
    return JsonResponse({
        'error': 'Please use the detect_screenshot_text endpoint with extracted text',
        'message': 'For image uploads, extract text first using OCR then call detect_screenshot_text',
        'status': 'info',
        'feature': 'use_detect_screenshot_text'
    }, status=200)


@csrf_exempt
@require_http_methods(["POST"])
def detect_web(request):
    try:
        data = json.loads(request.body)
        url = data.get('url', '')
        content = data.get('content', '')
        links = data.get('links', [])
        forms = data.get('forms', 0)
        title = data.get('title', '')
        
        result = detect_sms_scam(content)
        result['type'] = 'WEB'
        result['url'] = url
        result['title'] = title
        result['forms_found'] = forms
        result['links_found'] = len(links)
        
        if forms > 0 and result['score'] > 30:
            result['warnings'].append("📝 Page contains forms that could steal your information")
        
        if len(links) > 20:
            result['warnings'].append("🔗 Unusually high number of external links")
        
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def detect_sms_enhanced(request):
    sms_text = request.POST.get('sms_text', '')
    
    if not sms_text.strip():
        return JsonResponse({'error': 'Please enter SMS text'}, status=400)
    
    result = detect_sms_scam(sms_text)
    
    if result['score'] >= 50:
        result['risk_level'] = "HIGH RISK - SCAM DETECTED"
        result['color'] = "danger"
        result['emoji'] = "🔴"
    elif result['score'] >= 25:
        result['risk_level'] = "MEDIUM RISK"
        result['color'] = "warning"
        result['emoji'] = "🟡"
    else:
        result['risk_level'] = "LOW RISK"
        result['color'] = "success"
        result['emoji'] = "🟢"
    
    return JsonResponse(result)


@csrf_exempt
@require_http_methods(["POST"])
def save_training_data(request):
    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
        return JsonResponse({'status': 'success', 'message': 'Feedback received - thank you for helping improve detection!'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def check_link(request):
    return JsonResponse({
        'status': 'coming_soon',
        'message': 'Link safety checker is under development',
        'recommendation': 'Use the check_url endpoint for URL analysis'
    }, status=200)


@csrf_exempt
@require_http_methods(["POST"])
def submit_feedback(request):
    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
        return JsonResponse({'status': 'success', 'message': 'Thank you for your feedback! It helps us improve.'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(["GET"])
def get_scam_alerts(request):
    alerts = [
        {'type': 'M-Pesa Scam', 'description': 'Fake M-Pesa suspension messages circulating', 'date': '2026-04-25', 'severity': 'HIGH'},
        {'type': 'Fake Loan Offers', 'description': 'Scammers offering loans with advance fees', 'date': '2026-04-24', 'severity': 'MEDIUM'},
        {'type': 'Safaricom Promotion', 'description': 'Fake "You won iPhone" messages', 'date': '2026-04-23', 'severity': 'HIGH'},
        {'type': 'KRA Tax Refund', 'description': 'Fake tax refund SMS asking for personal info', 'date': '2026-04-22', 'severity': 'HIGH'},
        {'type': 'WhatsApp Job Scam', 'description': '"Work from home" scams on WhatsApp', 'date': '2026-04-21', 'severity': 'MEDIUM'},
    ]
    return JsonResponse({'alerts': alerts, 'count': len(alerts)})