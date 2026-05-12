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
from django.db.models import Avg
from django.contrib.auth.models import User
from django.shortcuts import render
from .models import Company, UserProfile, UserPoints, ScamReport, PhoneRisk, EmailRisk, UrlRisk, ScreenshotReport, WhatsAppRisk, BlockedNumber, Badge, UserBadge

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
        
def get_user_company(request):
    """Get user and company from request"""
    user = request.user if request.user.is_authenticated else None
    company = None
    if user and hasattr(user, 'userprofile'):
        company = user.userprofile.company
    return user, company


# ADD THESE TWO FUNCTIONS HERE (if they're missing):
def get_location_from_ip(ip_address):
    """Get approximate location from IP address"""
    if not ip_address or ip_address in ['127.0.0.1', 'localhost', 'anonymous']:
        return {
            'county': 'Nairobi',
            'latitude': -1.2921,
            'longitude': 36.8219,
        }
    try:
        import requests
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        data = response.json()
        if data.get('status') == 'success':
            return {
                'county': data.get('regionName', 'Unknown'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
            }
    except:
        pass
    return {'county': 'Unknown', 'latitude': -1.2921, 'longitude': 36.8219}


def map_to_kenyan_county(region_name):
    """Map IP region to Kenyan county"""
    county_map = {
        'Nairobi': 'Nairobi', 'Nairobi Area': 'Nairobi',
        'Mombasa': 'Mombasa', 'Coast': 'Mombasa',
        'Kisumu': 'Kisumu', 'Nyanza': 'Kisumu',
        'Nakuru': 'Nakuru', 'Rift Valley': 'Nakuru',
        'Uasin Gishu': 'Eldoret', 'Kiambu': 'Thika',
        'Machakos': 'Machakos', 'Kakamega': 'Kakamega',
        'Meru': 'Meru', 'Nyeri': 'Nyeri',
        'Garissa': 'Garissa', 'Laikipia': 'Nanyuki',
        'Embu': 'Embu',
    }
    return county_map.get(region_name, 'Nairobi')

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
        # Add these to your existing scam_patterns list (around line 200)

        # Investment Scams (Kenyan specific)
        (r'bitcoin.*?(investment|double|profit)', '₿ Crypto Scam', 'Fake cryptocurrency investment'),
        (r'forex.*?(trading|investment|signal)', '📊 Forex Scam', 'Fake forex trading scam'),
        (r'ponzi.*?(scheme|investment)', '📈 Ponzi Scheme', 'Ponzi/pyramid scheme scam'),
        (r'get rich quick', '💰 Get Rich Quick', 'Unrealistic wealth promises'),
        (r'passive income', '💤 Passive Income Scam', 'Fake passive income opportunity'),

        # Job Scams (Common in Kenya)
        (r'work from home.*?(earn|make|ksh)', '🏠 Work From Home', 'Fake remote job opening'),
        (r'data entry.*?(job|work)', '📝 Data Entry Job', 'Fake data entry position'),
        (r'online job.*?(registration|fee)', '💼 Online Job Scam', 'Job requiring upfront fee'),
        (r'position.*?(urgent|immediate).*?(salary|ksh)', '👔Urgent Hiring', 'Fake urgent job opening'),
        (r'cv.*?(update|submit).*?(link|click)', '📄 CV Update Scam', 'Fake CV update request'),

        # Loan Scams (Very common in Kenya)
        (r'loan.*?(approved|pre-approved).*?fee', '💰 Loan Fee Scam', 'Fake loan requiring processing fee'),
        (r'instant loan.*?(no credit|guaranteed)', '💵 Instant Loan', 'Fake instant loan offer'),
        (r'fuliza.*?(limit increase|upgrade)', '💳 Fuliza Scam', 'Fake Fuliza limit increase'),
        (r'm-shwari.*?(bonus|promotion)', '🏦 M-Shwari Scam', 'Fake M-Shwari bonus'),
        (r'kcb mpesa.*?(loan|advance)', '🏦 KCB M-PESA Scam', 'Fake KCB M-PESA loan'),

        # Government Benefits Scams
        (r'economic stimulus.*?(program|payment)', '💰 Stimulus Scam', 'Fake government stimulus'),
        (r'inuarisha.*?(bidii|program)', '📋 Inuarisha Scam', 'Fake Inuarisha program'),
        (r'kazi mtaani.*?(payment|registration)', '👷 Kazi Mtaani Scam', 'Fake Kazi Mtaani payment'),
        (r'hustler fund.*?(loan|application)', '💵 Hustler Fund Scam', 'Fake Hustler Fund offer'),

        # SMS Phishing (Smishing)
        (r'dial.*?\*.*?#.*?cancel', '📞 USSD Scam', 'Fake USSD code to dial'),
        (r'safaricom.*?(reward|points|bonus)', '🎁 Safaricom Rewards', 'Fake Safaricom reward'),
        (r'airtel.*?(reward|points|bonus)', '🎁 Airtel Rewards', 'Fake Airtel reward'),
        (r'telkom.*?(reward|points|bonus)', '🎁 Telkom Rewards', 'Fake Telkom reward'),

        # Fake Delivery Scams
        (r'(fedex|dhl|ups|posta).*?(delivery|package)', '📦 Delivery Scam', 'Fake package delivery'),
        (r'package.*?(held|pending|customs)', '📦 Package Hold Scam', 'Fake customs fee request'),
        (r'delivery.*?(fee|payment).*?ksh', '💰 Delivery Fee Scam', 'Fake delivery fee request'),

        # Family Emergency Scams
        (r'(son|daughter|child|mtoto).*?(accident|emergency)', '🚨 Family Emergency', 'Fake family emergency'),
        (r'(mum|dad|mom|father|mother).*?(hospital|accident)', '🏥 Parent Emergency', 'Fake parent emergency'),
        (r'(brother|sister|ndugu).*?(money|pesa|help)', '👨‍👩‍👧 Sibling Emergency', 'Fake sibling request'),

        # Formatted as: (pattern, emoji, message)
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
        
        # ============================================================
        # SAVE URL CHECK TO DATABASE WITH USER/COMPANY TRACKING
        # ============================================================
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                # Only try to get user if request has user attribute (public API won't)
                if hasattr(request, 'user'):
                    user, company = get_user_company(request)
                else:
                    user, company = None, None
                
                # Get location from IP
                ip = request.META.get('REMOTE_ADDR', 'anonymous')
                location = get_location_from_ip(ip)
                county = map_to_kenyan_county(location['county'])
                
                ScamReport.objects.create(
                    report_type='URL',
                    content=url[:500],
                    risk_score=score,
                    risk_level=risk_level,
                    reported_by=ip,
                    user=user,
                    company=company,
                    county=county,
                    latitude=location['latitude'],
                    longitude=location['longitude'],
                    ip_address=ip,
                )
            except Exception as e:
                print(f"URL save error: {e}")
        
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
        
        # ============================================================
        # SAVE SCREENSHOT CHECK TO DATABASE WITH USER/COMPANY TRACKING
        # ============================================================
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                user, company = get_user_company(request)
                
                # Get location from IP
                ip = request.META.get('REMOTE_ADDR', 'anonymous')
                location = get_location_from_ip(ip)
                county = map_to_kenyan_county(location['county'])
                
                ScamReport.objects.create(
                    report_type='SCREENSHOT',
                    content=extracted_text[:500],
                    risk_score=score,
                    risk_level=risk_level,
                    reported_by=ip,
                    user=user,
                    company=company,
                    county=county,
                    latitude=location['latitude'],
                    longitude=location['longitude'],
                    ip_address=ip,
                )
            except Exception as e:
                print(f"Screenshot save error: {e}")
        
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
    """Display scam alerts page with real-time data"""
    try:
        if MODELS_AVAILABLE and ScamReport.objects:
            recent_scams = ScamReport.objects.order_by('-date_reported')[:50]
            
            # Prepare data for template
            scams_data = []
            for scam in recent_scams:
                scams_data.append({
                    'type': scam.report_type,
                    'score': scam.risk_score,
                    'content': scam.content,
                    'date': scam.date_reported.strftime('%Y-%m-%d %H:%M'),
                })
        else:
            scams_data = []
        
        return render(request, 'detector/scam_alerts.html', {
            'recent_scams': scams_data
        })
    except Exception as e:
        print(f"Scam alerts error: {e}")
        return render(request, 'detector/scam_alerts.html', {'recent_scams': []})

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
        
        # Get keyword-based detection
        result = detect_sms_scam(sms_text)
        
        # ADD ML HYBRID SCORING
        try:
            from .ml.inference.predict import predict_scam
            ml_result = predict_scam(sms_text)
            if ml_result:
                keyword_score = result.get('score', 0)
                ml_score = ml_result.get('ml_score', 0)
                hybrid_score = round((keyword_score + ml_score) / 2, 1)
                
                result['ml_score'] = ml_score
                result['hybrid_score'] = hybrid_score
                result['ml_risk_level'] = ml_result.get('ml_risk_level')
                result['ml_confidence'] = ml_result.get('ml_confidence')
                result['model_name'] = ml_result.get('model_name')
                result['uses_ml'] = True
                result['score'] = hybrid_score
        except Exception as e:
            result['uses_ml'] = False
        
        # Normalize risk_level for frontend
        if 'risk_level' in result:
            if 'CRITICAL' in result['risk_level']:
                result['risk_level_display'] = 'CRITICAL'
                result['risk_level'] = 'CRITICAL'
            elif 'HIGH' in result['risk_level']:
                result['risk_level_display'] = 'HIGH'
                result['risk_level'] = 'HIGH'
            elif 'MEDIUM' in result['risk_level']:
                result['risk_level_display'] = 'MEDIUM'
                result['risk_level'] = 'MEDIUM'
            elif 'LOW' in result['risk_level']:
                result['risk_level_display'] = 'LOW'
                result['risk_level'] = 'LOW'
            else:
                result['risk_level'] = result['risk_level'].split(' - ')[0].strip()
        
        # Add color mapping
        if result['score'] >= 70:
            result['color'] = 'danger'
            result['badge_class'] = 'bg-danger'
        elif result['score'] >= 40:
            result['color'] = 'warning'
            result['badge_class'] = 'bg-warning'
        else:
            result['color'] = 'success'
            result['badge_class'] = 'bg-success'
        
        # ============================================================
        # SAVE WITH USER, COMPANY & LOCATION TRACKING
        # ============================================================
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                user, company = get_user_company(request)
                
                # Get location from IP
                ip = request.META.get('REMOTE_ADDR', 'anonymous')
                location = get_location_from_ip(ip)
                county = map_to_kenyan_county(location['county'])
                
                ScamReport.objects.create(
                    report_type='SMS',
                    content=sms_text[:500],
                    risk_score=result['score'],
                    risk_level=result.get('risk_level_display', result['risk_level']),
                    reported_by=request.META.get('REMOTE_ADDR', 'anonymous'),
                    user=user,
                    company=company,
                    county=county,
                    latitude=location['latitude'],
                    longitude=location['longitude'],
                    ip_address=ip,
                )
                
                # Award points for scam detection
                if result['score'] >= 40 and user:
                    award_points(user, 'detect_scam', 5)
                    
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
        
        # Get user and company for tracking
        user, company = get_user_company(request)
        
        # Get location from IP
        ip = request.META.get('REMOTE_ADDR', 'anonymous')
        location = get_location_from_ip(ip)
        county = map_to_kenyan_county(location['county'])
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='EMAIL',
                    content=email_text[:500],
                    risk_score=result['score'],
                    risk_level=result['risk_level'].split(' - ')[0] if ' - ' in result['risk_level'] else result['risk_level'],
                    reported_by=ip,
                    user=user,
                    company=company,
                    county=county,
                    latitude=location['latitude'],
                    longitude=location['longitude'],
                    ip_address=ip,
                )
                # Award points
                if result['score'] >= 40 and user:
                    award_points(user, 'detect_scam', 5)
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
        
        # Get user and company for tracking
        user, company = get_user_company(request)
        
        # Get location from IP
        ip = request.META.get('REMOTE_ADDR', 'anonymous')
        location = get_location_from_ip(ip)
        county = map_to_kenyan_county(location['county'])
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='WHATSAPP',
                    content=chat_text[:1000],
                    risk_score=result['score'],
                    risk_level=result['risk_level'].replace(' - SCAM DETECTED', ''),
                    reported_by=ip,
                    user=user,
                    company=company,
                    county=county,
                    latitude=location['latitude'],
                    longitude=location['longitude'],
                    ip_address=ip,
                )
                if result['score'] >= 40 and user:
                    award_points(user, 'detect_scam', 5)
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
        

# DETECT CALL ENDPOINT
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
        result['type'] = 'CALL'
        
        # Normalize risk_level for frontend
        if 'risk_level' in result:
            if 'CRITICAL' in result['risk_level']:
                result['risk_level'] = 'CRITICAL'
                result['risk_level_display'] = 'CRITICAL'
                result['color'] = 'danger'
                result['badge_class'] = 'bg-danger'
                result['emoji'] = '🔴🚨'
            elif 'HIGH' in result['risk_level']:
                result['risk_level'] = 'HIGH_RISK'
                result['risk_level_display'] = 'HIGH'
                result['color'] = 'danger'
                result['badge_class'] = 'bg-danger'
                result['emoji'] = '🔴'
            elif 'MEDIUM' in result['risk_level']:
                result['risk_level'] = 'MEDIUM_RISK'
                result['risk_level_display'] = 'MEDIUM'
                result['color'] = 'warning'
                result['badge_class'] = 'bg-warning'
                result['emoji'] = '🟡'
            else:
                result['risk_level'] = 'LOW_RISK'
                result['risk_level_display'] = 'LOW'
                result['color'] = 'success'
                result['badge_class'] = 'bg-success'
                result['emoji'] = '🟢'
        
        if 'score' not in result:
            result['score'] = result.get('combined_score', 0)
        if 'warnings' not in result:
            result['warnings'] = result.get('reasons', [])
        if 'message' not in result:
            if result['score'] >= 70:
                result['message'] = "🔴 CRITICAL: This call shows overwhelming scam indicators! HANG UP NOW!"
            elif result['score'] >= 50:
                result['message'] = "⚠️ This call shows strong scam indicators! HANG UP immediately."
            elif result['score'] >= 25:
                result['message'] = "⚠️ This call has suspicious elements. Verify through official channels."
            else:
                result['message'] = "✓ No scam patterns detected, but always exercise caution."
        
        # Get user and company for tracking
        user, company = get_user_company(request)
        
        # Get location from IP
        ip = request.META.get('REMOTE_ADDR', 'anonymous')
        location = get_location_from_ip(ip)
        county = map_to_kenyan_county(location['county'])
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='CALL',
                    content=transcript[:500],
                    risk_score=result.get('score', 0),
                    risk_level=result.get('risk_level_display', result.get('risk_level', 'LOW')),
                    reported_by=ip,
                    user=user,
                    company=company,
                    county=county,
                    latitude=location['latitude'],
                    longitude=location['longitude'],
                    ip_address=ip,
                )
                if result.get('score', 0) >= 40 and user:
                    award_points(user, 'detect_scam', 5)
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


#DETECT TELEGRAM ENDPOINT
@csrf_exempt
@require_http_methods(["POST"])
def detect_telegram(request):
    """Dedicated Telegram message detection - saves as TELEGRAM type"""
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            text = data.get('telegram_text', data.get('text', ''))
        else:
            text = request.POST.get('telegram_text', request.POST.get('text', ''))
        
        if not text or not text.strip():
            return JsonResponse({'error': 'Please enter text to analyze'}, status=400)
        
        result = detect_sms_scam(text)
        
        # Normalize risk_level
        if 'risk_level' in result:
            if 'CRITICAL' in result['risk_level']:
                result['risk_level_display'] = 'CRITICAL'
                result['risk_level'] = 'CRITICAL'
            elif 'HIGH' in result['risk_level']:
                result['risk_level_display'] = 'HIGH'
                result['risk_level'] = 'HIGH'
            elif 'MEDIUM' in result['risk_level']:
                result['risk_level_display'] = 'MEDIUM'
                result['risk_level'] = 'MEDIUM'
            elif 'LOW' in result['risk_level']:
                result['risk_level_display'] = 'LOW'
                result['risk_level'] = 'LOW'
        
        # Get user and company for tracking
        user, company = get_user_company(request)
        
        # Get location from IP
        ip = request.META.get('REMOTE_ADDR', 'anonymous')
        location = get_location_from_ip(ip)
        county = map_to_kenyan_county(location['county'])
        
        # Save as TELEGRAM type
        if MODELS_AVAILABLE and ScamReport.objects:
            ScamReport.objects.create(
                report_type='TELEGRAM',
                content=text[:500],
                risk_score=result['score'],
                risk_level=result.get('risk_level_display', result.get('risk_level', 'Unknown')),
                reported_by=ip,
                user=user,
                company=company,
                county=county,
                latitude=location['latitude'],
                longitude=location['longitude'],
                ip_address=ip,
            )
            if result['score'] >= 40 and user:
                award_points(user, 'detect_scam', 5)
        
        # Add color mapping
        if result['score'] >= 70:
            result['color'] = 'danger'
            result['badge_class'] = 'bg-danger'
        elif result['score'] >= 40:
            result['color'] = 'warning'
            result['badge_class'] = 'bg-warning'
        else:
            result['color'] = 'success'
            result['badge_class'] = 'bg-success'
        
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
        
        # Get user and company for tracking
        user, company = get_user_company(request)
        
        # Get location from IP
        ip = request.META.get('REMOTE_ADDR', 'anonymous')
        location = get_location_from_ip(ip)
        county = map_to_kenyan_county(location['county'])
        
        if MODELS_AVAILABLE and ScamReport.objects:
            try:
                ScamReport.objects.create(
                    report_type='CALL',
                    content=f"Reported scam number: {phone_number}\nDescription: {description}"[:500],
                    risk_score=85,
                    risk_level='HIGH',
                    reported_by=ip,
                    user=user,
                    company=company,
                    county=county,
                    latitude=location['latitude'],
                    longitude=location['longitude'],
                    ip_address=ip,
                )
            except Exception as e:
                print(f"Database save error: {e}")
        
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
# STATISTICS ENDPOINT
# detector/views.py - Add/Replace this get_stats function

from django.views.decorators.cache import cache_page
from django.core.cache import cache
from datetime import datetime, timedelta
from django.db.models import Avg, Count, Q
from django.utils import timezone
import json

@csrf_exempt
@require_http_methods(["GET"])
#@cache_page(60)  # Cache for 60 seconds to improve performance
def get_stats(request):
    """
    Get enhanced dashboard statistics filtered by user role
    - Anonymous: Empty stats
    - Individual User: Only their own reports
    - Company Admin: All reports for their company
    - Super Admin: All reports
    """
    try:
        if not MODELS_AVAILABLE or not ScamReport.objects:
            return JsonResponse({'success': True, 'stats': {}})
        
        user = request.user
        
        # ============ USER-BASED FILTERING ============
        if user.is_authenticated and user.is_superuser:
            reports = ScamReport.objects.all()
        elif user.is_authenticated:
            try:
                profile = user.userprofile
                if profile.can_view_all_company() and profile.company:
                    reports = ScamReport.objects.filter(company=profile.company)
                else:
                    reports = ScamReport.objects.filter(user=user)
            except:
                reports = ScamReport.objects.filter(user=user)
        else:
            # Anonymous - show empty
            reports = ScamReport.objects.none()
        
        # ============ BASIC COUNTS ============
        total_reports = reports.count()
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        today_count = reports.filter(date_reported__date=today).count()
        this_week_count = reports.filter(date_reported__date__gte=week_ago).count()
        this_month_count = reports.filter(date_reported__date__gte=month_ago).count()
        
        # ============ RISK LEVEL COUNTS ============
        high_risk_count = reports.filter(risk_score__gte=70).count()
        medium_risk_count = reports.filter(risk_score__gte=40, risk_score__lt=70).count()
        low_risk_count = reports.filter(risk_score__lt=40).count()
        
        # ============ TYPE BREAKDOWN ============
        sms_count = reports.filter(report_type='SMS').count()
        email_count = reports.filter(report_type='EMAIL').count()
        whatsapp_count = reports.filter(report_type='WHATSAPP').count()
        screenshot_count = reports.filter(report_type='SCREENSHOT').count()
        url_count = reports.filter(report_type='URL').count()
        call_count = reports.filter(report_type='CALL').count()
        telegram_count = reports.filter(report_type='TELEGRAM').count()
        
        # ============ AVERAGE SCORE ============
        avg_result = reports.aggregate(avg_score=Avg('risk_score'))
        average_risk_score = round(avg_result.get('avg_score', 0) or 0, 1)
        
        # ============ RISK DISTRIBUTION ============
        risk_distribution = {
            'high': high_risk_count,
            'medium': medium_risk_count,
            'low': low_risk_count
        }
        
        # ============ WEEKLY TREND ============
        weekly_trend = []
        weekly_labels = []
        for i in range(6, -1, -1):
            date = today - timedelta(days=i)
            count = reports.filter(date_reported__date=date).count()
            weekly_trend.append(count)
            weekly_labels.append(date.strftime('%a'))
        
        # ============ COUNTY BREAKDOWN ============
        county_data = []
        if user.is_authenticated:
            county_qs = reports.values('county').annotate(
                count=models.Count('id')
            ).order_by('-count')[:10]
            for c in county_qs:
                county_data.append({
                    'county': c['county'] or 'Unknown',
                    'count': c['count']
                })
        
        # ============ RECENT SCAMS ============
        recent_scams = reports.order_by('-date_reported')[:20]
        recent_data = []
        for r in recent_scams:
            recent_data.append({
                'id': r.id,
                'type': r.report_type,
                'score': r.risk_score,
                'level': 'HIGH' if r.risk_score >= 70 else 'MEDIUM' if r.risk_score >= 40 else 'LOW',
                'date': r.date_reported.strftime('%Y-%m-%d %H:%M'),
                'content': r.content[:150] + '...' if r.content and len(r.content) > 150 else r.content or 'No content',
                'preview': (r.content[:80] + '...') if r.content and len(r.content) > 80 else r.content,
                'county': r.county or 'Unknown',  # Added county to recent scams
            })
        
        # ============ STAFF SCANS (for company admin) ============
        staff_scans = []
        if user.is_authenticated:
            try:
                profile = user.userprofile
                if profile.can_view_all_company() and profile.company:
                    for staff_profile in profile.company.userprofile_set.filter(role='STAFF').select_related('user'):
                        staff_scans.append({
                            'name': staff_profile.user.username,
                            'scans': ScamReport.objects.filter(user=staff_profile.user).count(),
                            'high_risk': ScamReport.objects.filter(user=staff_profile.user, risk_score__gte=70).count(),
                            'today': ScamReport.objects.filter(user=staff_profile.user, date_reported__date=today).count(),
                        })
            except:
                pass
        
        # ============ RESPONSE ============
        return JsonResponse({
            'success': True,
            'is_authenticated': user.is_authenticated,
            'is_company_admin': user.is_authenticated and hasattr(user, 'userprofile') and user.userprofile.can_view_all_company(),
            'company_name': user.userprofile.company.name if user.is_authenticated and hasattr(user, 'userprofile') and user.userprofile.company else None,
            'staff_scans': staff_scans,
            'stats': {
                'total_reports': total_reports,
                'today_count': today_count,
                'this_week_count': this_week_count,
                'this_month_count': this_month_count,
                'high_risk_count': high_risk_count,
                'medium_risk_count': medium_risk_count,
                'low_risk_count': low_risk_count,
                'sms_count': sms_count,
                'email_count': email_count,
                'whatsapp_count': whatsapp_count,
                'screenshot_count': screenshot_count,
                'url_count': url_count,
                'call_count': call_count,
                'telegram_count': telegram_count,
                'average_risk_score': average_risk_score,
                'risk_distribution': risk_distribution,
                'weekly_trend': weekly_trend,
                'weekly_labels': weekly_labels,
                'recent_scams': recent_data,
                'county_data': county_data,  # Added county breakdown
            },
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'stats': {},
            'error': str(e),
            'status': 'error'
        })


def get_relative_time(date):
    """Convert datetime to relative time string (e.g., '2 hours ago')"""
    now = timezone.now()
    diff = now - date
    
    if diff.days > 7:
        return date.strftime('%b %d')
    elif diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"

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
    """
    Detect scams in web page content - Called by Chrome extension
    """
    try:
        data = json.loads(request.body)
        url = data.get('url', '')
        content = data.get('content', '')
        links = data.get('links', [])
        forms = data.get('forms', 0)
        title = data.get('title', '')
        
        # Use existing SMS detector for page content
        result = detect_sms_scam(content)
        
        # Add web-specific fields
        result['type'] = 'WEB'
        result['url'] = url
        result['title'] = title
        result['forms_found'] = forms
        result['links_found'] = len(links)
        
        # Additional web-specific warnings
        if forms > 0 and result['score'] > 30:
            result['warnings'].append("📝 Page contains forms that could steal your information")
        
        if len(links) > 20:
            result['warnings'].append("🔗 Unusually high number of external links")
        
        # Check for suspicious URL patterns
        suspicious_url_patterns = ['secure-', 'verify-', 'login-', 'update-', 'confirm-']
        if any(pattern in url.lower() for pattern in suspicious_url_patterns):
            result['score'] = min(100, result['score'] + 20)
            result['warnings'].append("⚠️ URL contains suspicious keywords")
            if result['score'] >= 70:
                result['risk_level'] = 'HIGH RISK'
        
        # Normalize score to 0-100
        result['score'] = min(100, max(0, result['score']))
        
        # Ensure risk_level is set
        if 'risk_level' not in result:
            if result['score'] >= 70:
                result['risk_level'] = 'HIGH RISK'
            elif result['score'] >= 40:
                result['risk_level'] = 'MEDIUM RISK'
            elif result['score'] >= 15:
                result['risk_level'] = 'LOW RISK'
            else:
                result['risk_level'] = 'SAFE'
        
        return JsonResponse(result)
        
    except Exception as e:
        return JsonResponse({
            'error': str(e),
            'score': 0,
            'risk_level': 'ERROR',
            'warnings': [f'Analysis error: {str(e)}'],
            'type': 'WEB'
        }, status=500)


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

# Add to views.py


from .unified_risk_engine import risk_engine, UnifiedRiskEngine
from .threat_intel import ThreatIntelligence

# Initialize global instances
risk_engine = UnifiedRiskEngine(use_ml=True)
threat_intel = ThreatIntelligence()


@csrf_exempt
@require_http_methods(["POST"])
def unified_detect(request):
    """
    Unified detection endpoint - handles all input types
    Expected JSON: {"type": "sms|email|url|phone|whatsapp", "content": "..."}
    """
    try:
        data = json.loads(request.body)
        detection_type = data.get('type', '').lower()
        content = data.get('content', '')
        
        if not content:
            return JsonResponse({'error': 'No content provided'}, status=400)
        
        # Route to appropriate detector
        if detection_type == 'sms':
            result = risk_engine.analyze_sms(content)
        elif detection_type == 'email':
            result = risk_engine.analyze_email(content)
        elif detection_type == 'url':
            # Also check threat intel
            threat_result = threat_intel.check_url(content)
            result = risk_engine.analyze_url(content)
            result['threat_intel'] = threat_result
        elif detection_type == 'phone':
            result = risk_engine.analyze_phone(content)
        elif detection_type == 'whatsapp':
            result = risk_engine.analyze_whatsapp(content)
        else:
            # Auto-detect type
            result = auto_detect_and_analyze(content, risk_engine)
        
        return JsonResponse({
            'success': True,
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def auto_detect_and_analyze(content, engine):
    """Auto-detect content type and analyze"""
    # Check if looks like URL
    if content.startswith(('http://', 'https://', 'www.')):
        return engine.analyze_url(content)
    
    # Check if looks like phone number
    if re.match(r'^\+?[\d\s\-\(\)]{10,15}$', content):
        return engine.analyze_phone(content)
    
    # Check if email-like
    if '@' in content and '.' in content:
        return engine.analyze_email(content)
    
    # Default to SMS
    return engine.analyze_sms(content)




@csrf_exempt
@require_http_methods(["POST"])
def train_ml(request):
    """Trigger ML training from existing reports"""
    try:
        # Train SMS model
        if risk_engine.ml_enhanced_sms:
            risk_engine.ml_enhanced_sms.train_from_existing_data(None)
            risk_engine.ml_enhanced_sms.save_model()
        
        return JsonResponse({
            'success': True,
            'message': 'ML models trained successfully',
            'metrics': risk_engine.ml_enhanced_sms.model_metrics if risk_engine.ml_enhanced_sms else {}
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
        
@csrf_exempt
@require_http_methods(["GET"])
def get_scam_alerts(request):
    """API endpoint for live alerts - used by the template"""
    alerts = [
        {'type': 'M-Pesa Scam', 'description': 'Fake M-Pesa suspension messages circulating', 'date': '2026-04-25', 'severity': 'HIGH'},
        {'type': 'Fake Loan Offers', 'description': 'Scammers offering loans with advance fees', 'date': '2026-04-24', 'severity': 'MEDIUM'},
        {'type': 'Safaricom Promotion', 'description': 'Fake "You won iPhone" messages', 'date': '2026-04-23', 'severity': 'HIGH'},
        {'type': 'KRA Tax Refund', 'description': 'Fake tax refund SMS asking for personal info', 'date': '2026-04-22', 'severity': 'HIGH'},
        {'type': 'WhatsApp Job Scam', 'description': '"Work from home" scams on WhatsApp', 'date': '2026-04-21', 'severity': 'MEDIUM'},
    ]
    return JsonResponse({'alerts': alerts, 'count': len(alerts)})
# Add this import at the top of views.py
from .ml.inference.predict import predict_scam, get_model_info

# Add this endpoint to views.py
@csrf_exempt
@require_http_methods(["POST", "GET"])
def predict_ml(request):
    """ML-based scam prediction endpoint (works without ML if unavailable)"""
    
    if request.method == "GET":
        try:
            from .ml.inference.predict import get_model_info
            info = get_model_info()
        except:
            info = {"is_loaded": False, "error": "ML not available"}
        return JsonResponse({'success': True, 'model_info': info})
    
    # POST - Predict
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            text = data.get('text', '')
        else:
            text = request.POST.get('text', '')
        
        if not text or not text.strip():
            return JsonResponse({'error': 'No text provided'}, status=400)
        
        # Try ML prediction
        ml_result = None
        try:
            from .ml.inference.predict import predict_scam
            ml_result = predict_scam(text)
        except Exception as e:
            print(f"ML unavailable: {e}")
        
        # Always get keyword-based detection
        keyword_result = detect_sms_scam(text)
        keyword_score = keyword_result.get('score', 0)
        
        # Hybrid or keyword-only score
        if ml_result:
            ml_score = ml_result.get('ml_score', 0)
            hybrid_score = round((keyword_score + ml_score) / 2, 1)
            uses_ml = True
        else:
            ml_score = 0
            hybrid_score = keyword_score
            uses_ml = False
        
        # Final risk level
        if hybrid_score >= 70:
            final_risk = "HIGH RISK"
        elif hybrid_score >= 40:
            final_risk = "MEDIUM RISK"
        elif hybrid_score >= 20:
            final_risk = "LOW RISK"
        else:
            final_risk = "SAFE"
        
        return JsonResponse({
            'success': True,
            'text': text[:200],
            'hybrid_score': hybrid_score,
            'hybrid_risk_level': final_risk,
            'hybrid_is_scam': hybrid_score >= 50,
            'uses_ml': uses_ml,
            'ml_prediction': {
                'score': ml_score,
                'risk_level': ml_result.get('ml_risk_level') if ml_result else 'N/A',
                'is_scam': ml_result.get('ml_is_scam') if ml_result else False,
                'confidence': ml_result.get('ml_confidence') if ml_result else 0,
                'model': ml_result.get('model_name') if ml_result else 'N/A',
            } if uses_ml else None,
            'keyword_prediction': {
                'score': keyword_score,
                'risk_level': keyword_result.get('risk_level'),
                'warnings': keyword_result.get('warnings', [])[:5],
            },
            'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
@csrf_exempt
@require_http_methods(["POST"])
def report_number(request):
    """Report a scam phone number"""
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            phone_number = data.get('phone_number', '')
            category = data.get('category', '')
            description = data.get('description', '')
        else:
            phone_number = request.POST.get('phone_number', '')
            category = request.POST.get('category', '')
            description = request.POST.get('description', '')
        
        if not phone_number:
            return JsonResponse({'error': 'Phone number required'}, status=400)
        
        cleaned = phone_number.strip().replace('-', '').replace(' ', '').replace('+', '')
        if cleaned.startswith('0'):
            cleaned = '254' + cleaned[1:]
        elif not cleaned.startswith('254'):
            cleaned = '254' + cleaned[-9:]
        
        if MODELS_AVAILABLE:
            from .models import BlockedNumber
            
            number, created = BlockedNumber.objects.get_or_create(
                phone_number=cleaned,
                defaults={
                    'report_count': 1,
                    'scam_category': category or '',
                    'description': description or '',
                    'reported_by': request.META.get('REMOTE_ADDR', 'anonymous')
                }
            )
            
            if not created:
                number.report_count += 1
                number.last_reported = timezone.now()
                if category:
                    number.scam_category = category
                if description:
                    number.description = description
                number.calculate_confidence()
                number.save(update_fields=['report_count', 'last_reported', 'scam_category', 'description', 'confidence_score', 'status'])
            
            # Award points for reporting
            if request.user.is_authenticated:
                award_points(request.user, 'report_number', 50)
            
            return JsonResponse({
                'success': True,
                'created': created,
                'phone_number': cleaned,
                'report_count': number.report_count,
                'confidence': round(number.confidence_score, 1),
                'status': number.status
            })
        
        return JsonResponse({'success': True, 'message': 'Report received'})
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def vote_number(request):
    """Upvote or downvote a reported number"""
    try:
        data = json.loads(request.body)
        phone_number = data.get('phone_number', '')
        vote_type = data.get('vote', 'up')
        
        if not phone_number:
            return JsonResponse({'error': 'Phone number required'}, status=400)
        
        cleaned = phone_number.strip().replace('-', '').replace(' ', '').replace('+', '')
        if cleaned.startswith('0'):
            cleaned = '254' + cleaned[1:]
        
        if MODELS_AVAILABLE:
            from .models import BlockedNumber
            
            try:
                number = BlockedNumber.objects.get(phone_number=cleaned)
                if vote_type == 'up':
                    number.upvotes += 1
                else:
                    number.downvotes += 1
                number.calculate_confidence()
                number.save()
                
                return JsonResponse({
                    'success': True,
                    'phone_number': cleaned,
                    'upvotes': number.upvotes,
                    'downvotes': number.downvotes,
                    'confidence': number.confidence_score,
                    'status': number.status
                })
            except BlockedNumber.DoesNotExist:
                return JsonResponse({'error': 'Number not found in blocklist'}, status=404)
        
        return JsonResponse({'error': 'Database not available'}, status=503)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def check_blocklist(request, phone_number=None):
    """Check if a number is in the blocklist"""
    if not phone_number:
        phone_number = request.GET.get('phone', '')
    
    if not phone_number:
        return JsonResponse({'error': 'Phone number required'}, status=400)
    
    cleaned = phone_number.strip().replace('-', '').replace(' ', '').replace('+', '')
    if cleaned.startswith('0'):
        cleaned = '254' + cleaned[1:]
    
    if MODELS_AVAILABLE:
        from .models import BlockedNumber
        try:
            number = BlockedNumber.objects.get(phone_number=cleaned)
            return JsonResponse({
                'found': True,
                'phone_number': cleaned,
                'is_blocked': number.status in ['CONFIRMED', 'BLOCKED'],
                'report_count': number.report_count,
                'confidence': number.confidence_score,
                'status': number.status,
                'category': number.scam_category
            })
        except BlockedNumber.DoesNotExist:
            return JsonResponse({
                'found': False,
                'phone_number': cleaned,
                'is_blocked': False
            })
    
    return JsonResponse({'error': 'Database not available'}, status=503)


@csrf_exempt
@require_http_methods(["GET"])
def top_scam_numbers(request):
    """Get top reported scam numbers"""
    limit = int(request.GET.get('limit', 20))
    
    if MODELS_AVAILABLE:
        from .models import BlockedNumber
        numbers = BlockedNumber.objects.filter(
            status__in=['CONFIRMED', 'BLOCKED']
        ).order_by('-confidence_score')[:limit]
        
        return JsonResponse({
            'count': numbers.count(),
            'numbers': [
                {
                    'phone': n.phone_number,
                    'reports': n.report_count,
                    'confidence': n.confidence_score,
                    'category': n.scam_category
                }
                for n in numbers
            ]
        })
    
    return JsonResponse({'error': 'Database not available'}, status=503)

@csrf_exempt
@require_http_methods(["POST"])
def analyze_forwarded_email(request):
    """Webhook to analyze forwarded emails"""
    try:
        # Get raw email from request
        raw_email = request.body
        
        if not raw_email:
            return JsonResponse({'error': 'No email content provided'}, status=400)
        
        from detector.email_forward.parser import EmailParser
        from detector.email_forward.analyzer import EmailAnalyzer
        
        # Parse email
        parsed = EmailParser.parse_email(raw_email)
        
        if parsed.get('error'):
            return JsonResponse({'error': parsed['error']}, status=400)
        
        # Analyze
        analysis = EmailAnalyzer.analyze(parsed)
        
        # ============================================================
        # SAVE WITH USER MATCHING
        # ============================================================
        if MODELS_AVAILABLE and ScamReport.objects:
            import re
            
            # Try to match sender to a registered user
            from_addr = parsed.get('from', '')
            user = None
            company = None
            
            # Extract email from "Name <email>" format
            email_match = re.search(r'<(.+?)>', from_addr)
            sender_email = email_match.group(1) if email_match else from_addr
            
            # Try to find user by email
            if sender_email:
                try:
                    user = User.objects.filter(email__iexact=sender_email).first()
                    if user and hasattr(user, 'userprofile') and user.userprofile.company:
                        company = user.userprofile.company
                except:
                    pass
            
            ScamReport.objects.create(
                report_type='EMAIL',
                content=parsed.get('body_text', '')[:500],
                risk_score=analysis['score'],
                risk_level=analysis['risk_level'],
                reported_by=request.META.get('REMOTE_ADDR', 'anonymous'),
                user=user,
                company=company,
            )
        
        # Build response for auto-reply
        response = build_email_response(parsed, analysis)
        
        return JsonResponse({
            'success': True,
            'analysis': analysis,
            'parsed': {
                'subject': parsed.get('subject'),
                'from': parsed.get('from'),
                'urls_found': len(parsed.get('urls', []))
            },
            'auto_reply': response
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    

def build_email_response(parsed, analysis):
    """Build auto-reply email content"""
    score = analysis['score']
    
    if score >= 70:
        emoji = "🚨🔴"
        verdict = "SCAM / PHISHING CONFIRMED"
    elif score >= 40:
        emoji = "⚠️🟡"
        verdict = "SUSPICIOUS - Exercise Caution"
    else:
        emoji = "✅🟢"
        verdict = "Appears Safe"
    
    response = """Subject: {emoji} Email Analysis: {verdict}

Thank you for forwarding this email to AI Fraud Shield.

====================================
ANALYSIS RESULTS
====================================
Risk Score: {score}/100
Risk Level: {analysis['risk_level']}
Verdict: {verdict}

Body Analysis Score: {analysis['body_score']}/100
Subject Analysis: {analysis['subject_score']}/100
URL Risk Score: {analysis['url_score']}/100

URLs Found: {analysis['urls_found']}
Suspicious URLs: {len(analysis['suspicious_urls'])}
"""
    
    if analysis['suspicious_urls']:
        response += "\n⚠️ Suspicious URLs Detected:\n"
        for u in analysis['suspicious_urls'][:3]:
            response += f"  • {u['url'][:80]}\n"
    
    if analysis['warnings']:
        response += "\n🔍 Warning Indicators:\n"
        for w in analysis['warnings'][:3]:
            response += f"  • {w}\n"
    
    response += "\n💡 Recommendations:\n"
    for r in analysis['recommendations']:
        response += f"  • {r}\n"
    
    response += """
====================================
📞 Report: SMS 333 (Safaricom)
📧 Forward phishing: report@kenyacic.go.ke
🛡️ Powered by AI Fraud Shield - fraudshield.ke
"""
    
    return response
@csrf_exempt
@require_http_methods(["GET"])
def recent_activity(request):
    try:
        if not MODELS_AVAILABLE or not ScamReport.objects:
            return JsonResponse({'activities': []})
        
        from django.utils import timezone
        recent = ScamReport.objects.order_by('-date_reported')[:15]
        
        activities = []
        for r in recent:
            config = {
                'SMS': {'icon': '📱', 'color': '#17a2b8'},
                'EMAIL': {'icon': '📧', 'color': '#fd7e14'},
                'WHATSAPP': {'icon': '💬', 'color': '#20c997'},
                'TELEGRAM': {'icon': '🤖', 'color': '#0088cc'},
                'CALL': {'icon': '📞', 'color': '#dc3545'},
                'URL': {'icon': '🔗', 'color': '#6610f2'},
            }.get(r.report_type, {'icon': '📋', 'color': '#6c757d'})
            
            now = timezone.now()
            diff = now - r.date_reported
            if diff.days > 7: time_str = r.date_reported.strftime('%b %d')
            elif diff.days > 0: time_str = f"{diff.days}d ago"
            elif diff.seconds > 3600: time_str = f"{diff.seconds // 3600}h ago"
            elif diff.seconds > 60: time_str = f"{diff.seconds // 60}m ago"
            else: time_str = "Just now"
            
            activities.append({
                'type': r.report_type,
                'icon': config['icon'],
                'color': config['color'],
                'preview': (r.content or '')[:80],
                'score': r.risk_score,
                'time': time_str
            })
        
        return JsonResponse({'activities': activities})
    except Exception as e:
        return JsonResponse({'activities': []})
    

# ============================================================
# MULTI-TENANT COMPANY MANAGEMENT
# ============================================================

@csrf_exempt
@require_http_methods(["GET"])
def get_user_stats(request):
    """Get stats filtered by user's role and company"""
    user = request.user
    
    if not user.is_authenticated:
        return JsonResponse({
            'success': True,
            'label': 'Public',
            'is_company_admin': False,
            'stats': {
                'total_reports': 0,
                'today_count': 0,
                'high_risk_count': 0,
                'sms_count': 0,
                'email_count': 0,
                'call_count': 0,
            }
        })
    
    try:
        profile = user.userprofile
        is_admin = profile.can_view_all_company()
        company = profile.company
    except:
        profile = None
        is_admin = False
        company = None
    
    # Determine which reports to show
    if is_admin and company:
        reports = ScamReport.objects.filter(company=company)
        label = f"{company.name} - All Staff"
        total_staff = company.userprofile_set.count()
        
        # Get per-staff stats
        staff_scans = []
        for staff_profile in company.userprofile_set.filter(role='STAFF').select_related('user'):
            staff_scans.append({
                'name': staff_profile.user.username,
                'scans': ScamReport.objects.filter(user=staff_profile.user).count(),
                'high_risk': ScamReport.objects.filter(user=staff_profile.user, risk_score__gte=70).count(),
                'today': ScamReport.objects.filter(user=staff_profile.user, date_reported__date=timezone.now().date()).count(),
            })
    else:
        reports = ScamReport.objects.filter(user=user) if user.is_authenticated else ScamReport.objects.none()
        label = user.username if user.is_authenticated else 'Public'
        total_staff = 0
        staff_scans = []
    
    today = timezone.now().date()
    
    return JsonResponse({
        'success': True,
        'label': label,
        'is_company_admin': is_admin,
        'company_name': company.name if company else None,
        'total_staff': total_staff,
        'staff_scans': sorted(staff_scans, key=lambda x: x['scans'], reverse=True)[:10],
        'stats': {
            'total_reports': reports.count(),
            'today_count': reports.filter(date_reported__date=today).count(),
            'high_risk_count': reports.filter(risk_score__gte=70).count(),
            'sms_count': reports.filter(report_type='SMS').count(),
            'email_count': reports.filter(report_type='EMAIL').count(),
            'call_count': reports.filter(report_type='CALL').count(),
        }
    })


@csrf_exempt
@require_http_methods(["POST"])
def create_company(request):
    """Create a new company (super admin only)"""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Only super admins can create companies'}, status=403)
    
    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
        name = data.get('name', '')
        email = data.get('email', '')
        phone = data.get('phone', '')
        
        if not name:
            return JsonResponse({'error': 'Company name required'}, status=400)
        
        slug = name.lower().replace(' ', '-')
        
        company = Company.objects.create(
            name=name,
            slug=slug,
            email=email,
            phone=phone,
            created_by=request.user
        )
        
        # Make the creator the company admin
        UserProfile.objects.create(
            user=request.user,
            company=company,
            role='COMPANY_ADMIN'
        )
        
        return JsonResponse({
            'success': True,
            'company_id': company.id,
            'company_name': company.name,
            'slug': company.slug
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def add_staff_to_company(request):
    """Add a staff member to a company (company admin only)"""
    try:
        profile = request.user.userprofile
        if not profile.can_view_all_company():
            return JsonResponse({'error': 'Only company admins can add staff'}, status=403)
        
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
        username = data.get('username', '')
        email = data.get('email', '')
        
        # Find or create user
        from django.contrib.auth.models import User
        user = User.objects.filter(username=username).first()
        if not user:
            # Create new user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=data.get('password', 'staff123')
            )
        
        # Create profile linked to company
        staff_profile, created = UserProfile.objects.get_or_create(
            user=user,
            defaults={
                'company': profile.company,
                'role': 'STAFF',
                'department': data.get('department', '')
            }
        )
        
        if not created and staff_profile.company != profile.company:
            staff_profile.company = profile.company
            staff_profile.role = 'STAFF'
            staff_profile.save()
        
        return JsonResponse({
            'success': True,
            'created': created,
            'username': user.username,
            'staff_id': user.id
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def my_company(request):
    """Get current user's company info"""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Login required'}, status=401)
    
    try:
        profile = request.user.userprofile
        company = profile.company
        
        if not company:
            return JsonResponse({
                'has_company': False,
                'role': profile.role,
                'message': 'You are an individual user. Create or join a company for team features.'
            })
        
        staff = UserProfile.objects.filter(company=company).select_related('user')
        
        return JsonResponse({
            'has_company': True,
            'company': {
                'name': company.name,
                'email': company.email,
                'phone': company.phone,
                'created_at': company.created_at.strftime('%Y-%m-%d'),
            },
            'my_role': profile.role,
            'is_admin': profile.can_view_all_company(),
            'total_staff': staff.count(),
            'staff': [
                {
                    'username': s.user.username,
                    'role': s.role,
                    'department': s.department,
                    'scans': ScamReport.objects.filter(user=s.user).count(),
                }
                for s in staff
            ]
        })
        
    except UserProfile.DoesNotExist:
        return JsonResponse({
            'has_company': False,
            'message': 'Profile not found. Contact admin.'
        }, status=404)
        
@csrf_exempt
@require_http_methods(["POST", "GET"])
def register_user(request):
    """Register a new user with role selection"""
    
    if request.method == "GET":
        return render(request, 'detector/register.html')
    
    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
        
        username = data.get('username', '')
        email = data.get('email', '')
        password = data.get('password', '')
        role = data.get('role', 'INDIVIDUAL')
        company_code = data.get('company_code', '')  # For joining existing company
        
        if not username or not password:
            return JsonResponse({'error': 'Username and password required'}, status=400)
        
        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already taken'}, status=400)
        
        # Create user
        user = User.objects.create_user(username=username, email=email, password=password)
        
        # Handle role and company
        company = None
        
        if role == 'COMPANY_ADMIN':
            # Create new company
            company_name = data.get('company_name', f"{username}'s Company")
            company = Company.objects.create(
                name=company_name,
                slug=username.lower(),
                email=email,
                created_by=user
            )
        
        elif role == 'STAFF' and company_code:
            # Join existing company
            try:
                company = Company.objects.get(slug=company_code)
            except Company.DoesNotExist:
                return JsonResponse({'error': 'Invalid company code'}, status=400)
        
        # Create profile
        UserProfile.objects.create(
            user=user,
            company=company,
            role=role,
        )
        
        # Auto-login
        from django.contrib.auth import login
        login(request, user)
        
        return JsonResponse({
            'success': True,
            'message': 'Registration successful!',
            'username': username,
            'role': role,
            'company': company.name if company else None,
            'redirect': '/'
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def get_company_info(request, slug):
    """Get public info about a company (for staff joining)"""
    try:
        company = Company.objects.get(slug=slug)
        return JsonResponse({
            'name': company.name,
            'slug': company.slug,
            'staff_count': company.userprofile_set.count(),
        })
    except Company.DoesNotExist:
        return JsonResponse({'error': 'Company not found'}, status=404)
    
#############################
#HEAT MAP DATA ENDPOINT
#############################



def scam_heatmap(request):
    """Display scam activity heatmap for Kenya"""
    try:
        import folium
        from folium.plugins import HeatMap
        
        # Get filter parameters
        scam_type = request.GET.get('type', 'all')
        time_range = request.GET.get('time', 'all')
        
        # Kenya center coordinates
        kenya_center = [-0.0236, 37.9062]
        
        # Create map
        m = folium.Map(
            location=kenya_center,
            zoom_start=7,
            tiles='CartoDB dark_matter',
            attr='AI Fraud Shield'
        )
        
        # County coordinates
        county_coords = {
            'Nairobi': [-1.2921, 36.8219],
            'Mombasa': [-4.0435, 39.6682],
            'Kisumu': [-0.0917, 34.7680],
            'Nakuru': [-0.3031, 36.0800],
            'Eldoret': [0.5143, 35.2698],
            'Thika': [-1.0396, 37.0695],
            'Malindi': [-3.2175, 40.1167],
            'Kitale': [1.0187, 35.0062],
            'Garissa': [-0.4532, 39.6460],
            'Nyeri': [-0.4201, 36.9516],
            'Meru': [0.0500, 37.6500],
            'Machakos': [-1.5177, 37.2634],
            'Kakamega': [0.2833, 34.7500],
            'Embu': [-0.5311, 37.4500],
            'Nanyuki': [0.0167, 37.0667],
            'Kisii': [-0.6816, 34.7775],
            'Lamu': [-2.2696, 40.9006],
            'Narok': [-1.0717, 35.8647],
            'Voi': [-3.3967, 38.5559],
            'Mandera': [3.9417, 41.8667],
        }
        
        county_counts = {c: 0 for c in county_coords}
        county_counts['Other'] = 0
        total_scams = 0
        high_risk = 0
        heat_data = []
        
        if MODELS_AVAILABLE and ScamReport.objects:
            reports = ScamReport.objects.filter(risk_score__gte=40)
            
            # Apply type filter
            if scam_type != 'all':
                reports = reports.filter(report_type=scam_type)
            
            # Apply time filter
            today = timezone.now().date()
            if time_range == 'today':
                reports = reports.filter(date_reported__date=today)
            elif time_range == 'week':
                reports = reports.filter(date_reported__date__gte=today - timedelta(days=7))
            elif time_range == 'month':
                reports = reports.filter(date_reported__date__gte=today - timedelta(days=30))
            
            # ============================================================
            # FIXED: Get counts BEFORE slicing
            # ============================================================
            total_scams = reports.count()
            high_risk = reports.filter(risk_score__gte=70).count()
            
            # NOW slice for display (limit to 200 markers)
            reports = reports[:200]
            
            for report in reports:
                # Use REAL county/location data
                if report.latitude and report.longitude:
                    coords = [report.latitude, report.longitude]
                    county = report.county if report.county else 'Unknown'
                elif report.county and report.county in county_coords:
                    coords = county_coords[report.county]
                    county = report.county
                else:
                    county = 'Nairobi'
                    coords = county_coords['Nairobi']
                
                if county in county_counts:
                    county_counts[county] += 1
                else:
                    county_counts['Other'] += 1
                
                if report.risk_score >= 70:
                    color = 'red'
                elif report.risk_score >= 50:
                    color = 'orange'
                else:
                    color = 'yellow'
                
                folium.CircleMarker(
                    location=coords,
                    radius=5 + (report.risk_score / 10),
                    popup=f"<b>{report.report_type}</b><br>Score: {report.risk_score}/100<br>County: {county}",
                    color=color,
                    fill=True,
                    fillOpacity=0.6
                ).add_to(m)
                
                heat_data.append([coords[0], coords[1], report.risk_score / 100])
            
            if heat_data:
                HeatMap(heat_data, radius=25, blur=15, max_zoom=10).add_to(m)
        
        # Add county markers
        for county, coords in county_coords.items():
            count = county_counts.get(county, 0)
            if count > 0:
                folium.Marker(
                    coords,
                    popup=f"<b>{county}</b><br>Scam Reports: {count}",
                    icon=folium.Icon(color='blue', icon='info-sign')
                ).add_to(m)
        
        # Add legend
        legend_html = '''
        <div style="position:fixed;bottom:50px;left:50px;z-index:9999;background:white;padding:10px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.3);font-family:sans-serif;font-size:12px;">
            <strong>🗺️ Scam Risk Levels</strong><br>
            <span style="color:red;">●</span> High Risk (70+)<br>
            <span style="color:orange;">●</span> Medium Risk (50-69)<br>
            <span style="color:yellow;">●</span> Low Risk (40-49)<br>
            <span style="color:blue;">▼</span> County Center
        </div>
        '''
        m.get_root().html.add_child(folium.Element(legend_html))
        
        # Build county stats
        county_stats = []
        for county, count in sorted(county_counts.items(), key=lambda x: x[1], reverse=True):
            if count > 0 and county != 'Other':
                pct = min(100, (count / max(1, total_scams)) * 100)
                county_stats.append({
                    'name': county,
                    'count': count,
                    'percentage': round(pct, 1)
                })
        
        blocked = 0
        if MODELS_AVAILABLE:
            try:
                from .models import BlockedNumber
                blocked = BlockedNumber.objects.filter(status__in=['CONFIRMED', 'BLOCKED']).count()
            except:
                pass
        
        map_html = m._repr_html_()
        
        return render(request, 'detector/heatmap.html', {
            'map_html': map_html,
            'total_scams': total_scams,
            'high_risk': high_risk,
            'active_counties': len([c for c in county_stats if c['count'] > 0]),
            'blocked_numbers': blocked,
            'county_stats': county_stats[:15],
            'current_filter': scam_type,
            'current_time': time_range,
        })
        
    except ImportError:
        return render(request, 'detector/heatmap.html', {
            'error': 'Map library not installed. Run: pip install folium',
            'total_scams': 0, 'high_risk': 0, 'active_counties': 0,
            'blocked_numbers': 0, 'county_stats': [],
        })
    except Exception as e:
        return render(request, 'detector/heatmap.html', {
            'error': str(e),
            'total_scams': 0, 'high_risk': 0, 'active_counties': 0,
            'blocked_numbers': 0, 'county_stats': [],
        })
        
# ============================================================
# Rewards and Gamification Endpoints
# ============================================================
POINTS_MAP = {
    'detect_scam': 5,      # Detecting a scam
    'report_number': 50,   # Reporting a scam number
    'verify_scam': 20,     # Verification confirmed
    'block_number': 30,    # Number gets blocked
    'daily_login': 10,     # Daily activity
    'share_report': 15,    # Sharing results
}

def award_points(user, action_type, points=None):
    """Award points to user for actions"""
    if not user or not user.is_authenticated:
        return None
    
    if points is None:
        points = POINTS_MAP.get(action_type, 5)
    
    try:
        user_points, created = UserPoints.objects.get_or_create(user=user)
        user_points.add_points(points, action_type)
        
        # Check for badges
        check_and_award_badges(user, user_points)
        
        return user_points
    except Exception as e:
        print(f"Points error: {e}")
        return None


def check_and_award_badges(user, user_points):
    """Check and award badges based on achievements"""
    badges_to_check = [
        {'cond': user_points.total_points >= 100, 'name': 'First 100'},
        {'cond': user_points.total_points >= 500, 'name': 'Rising Star'},
        {'cond': user_points.total_points >= 1000, 'name': 'Scam Hunter'},
        {'cond': user_points.reports_submitted >= 10, 'name': 'Reporter'},
        {'cond': user_points.reports_submitted >= 50, 'name': 'Watchdog'},
        {'cond': user_points.scams_verified >= 20, 'name': 'Verifier'},
        {'cond': user_points.numbers_blocked >= 5, 'name': 'Blocker'},
        {'cond': user_points.current_streak >= 7, 'name': 'Dedicated'},
    ]
    
    for check in badges_to_check:
        if check['cond']:
            badge, created = Badge.objects.get_or_create(
                name=check['name'],
                defaults={'description': f'Earned the {check["name"]} badge', 'icon': '🏅'}
            )
            UserBadge.objects.get_or_create(user=user, badge=badge)


@csrf_exempt
@require_http_methods(["GET"])
def leaderboard(request):
    """Get top users by points"""
    limit = int(request.GET.get('limit', 20))
    
    top_users = UserPoints.objects.select_related('user').order_by('-total_points')[:limit]
    
    leaderboard_data = []
    for rank, up in enumerate(top_users, 1):
        leaderboard_data.append({
            'rank': rank,
            'username': up.user.username,
            'points': up.total_points,
            'level': up.get_level(),
            'reports': up.reports_submitted,
            'badges': UserBadge.objects.filter(user=up.user).count(),
        })
    
    return JsonResponse({
        'leaderboard': leaderboard_data,
        'total_users': UserPoints.objects.count(),
    })


@csrf_exempt
@require_http_methods(["GET"])
def my_points(request):
    """Get current user's points"""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Login required'}, status=401)
    
    try:
        up = UserPoints.objects.get(user=request.user)
        badges = UserBadge.objects.filter(user=request.user).select_related('badge')
        
        return JsonResponse({
            'points': up.total_points,
            'level': up.get_level(),
            'reports': up.reports_submitted,
            'verified': up.scams_verified,
            'blocked': up.numbers_blocked,
            'streak': up.current_streak,
            'badges': [{'name': b.badge.name, 'icon': b.badge.icon} for b in badges],
        })
    except UserPoints.DoesNotExist:
        return JsonResponse({
            'points': 0, 'level': '🌱 Newcomer',
            'reports': 0, 'verified': 0, 'blocked': 0, 'streak': 0, 'badges': []
        })
def leaderboard_page(request):
    """Display leaderboard page"""
    return render(request, 'detector/leaderboard.html')