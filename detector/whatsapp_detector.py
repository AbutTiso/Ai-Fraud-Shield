# detector/whatsapp_detector.py
import re
from datetime import datetime

def detect_whatsapp_scam(chat_text):
    """Detect scams in exported WhatsApp chats"""
    
    lines = chat_text.split('\n')
    score = 0
    warnings = []
    suspicious_messages = []
    
    # Common WhatsApp scam patterns in Kenya
    scam_patterns = [
        (r'send.*?money.*?to.*?\d{10}', 'Money request with phone number', 12),
        (r'urgent.*?help.*?money', 'Urgent money request', 12),
        (r'free.*?prize.*?click', 'Fake prize/lottery', 15),
        (r'verify.*?account.*?link', 'Account verification scam', 12),
        (r'job.*?opportunity.*?pay.*?first', 'Fake job requiring payment', 12),
        (r'loan.*?offer.*?processing.*?fee', 'Fake loan advance fee', 12),
        (r'win.*?iphone.*?safaricom', 'Fake Safaricom promotion', 15),
        (r'investment.*?double.*?money', 'Ponzi scheme', 15),
        (r'gift.*?card.*?send.*?code', 'Gift card scam', 12),
        (r'whatsapp.*?gold.*?number', 'WhatsApp gold scam', 15),
        (r'congratulations.*?selected', 'Fake congratulations message', 10),
        (r'limited.*?time.*?offer', 'Urgency pressure tactic', 10),
        (r'click.*?link.*?claim', 'Link claiming scam', 10),
    ]
    
    # Check each line
    for i, line in enumerate(lines):
        line_lower = line.lower()
        
        for pattern, description, points in scam_patterns:
            if re.search(pattern, line_lower):
                score += points
                warning_msg = f"Line {i+1}: {description}"
                if warning_msg not in warnings:
                    warnings.append(f"⚠️ {warning_msg}")
                    suspicious_messages.append(line[:100])
        
        # Check for URLs
        if re.search(r'http[s]?://\S+', line_lower):
            score += 8
            if "Contains URL" not in str(warnings):
                warnings.append("🔗 Suspicious link detected")
        
        # Check for phone numbers
        if re.search(r'(07|01|2547)\d{8}', line_lower):
            score += 8
            if "Phone number" not in str(warnings):
                warnings.append("📞 Unsolicited phone number detected")
        
        # Check for money requests
        if re.search(r'(ksh|kes|shillings?)\s*\d+', line_lower):
            score += 10
            if "Money request" not in str(warnings):
                warnings.append("💰 Money request detected - be very cautious")
        
        # Check for personal info requests
        if re.search(r'(pin|password|mpin|otp|verify|confirm)', line_lower):
            score += 15
            warnings.append("🔐 Request for sensitive information - SCAM TACTIC!")
    
    # Check for single sender spamming
    unique_senders = set()
    for line in lines[:50]:
        match = re.match(r'(\d{1,2}/\d{1,2}/\d{4}), (\d{1,2}:\d{2}) - ([^:]+):', line)
        if match:
            sender = match.group(3).strip()
            unique_senders.add(sender)
    
    if len(unique_senders) == 1 and len(lines) > 20:
        score += 15
        warnings.append("📨 Single sender with many messages - potential spam campaign")
    
    # Cap score
    score = min(100, score)
    
    # Determine risk
    if score >= 50:
        risk_level = "HIGH RISK - SCAM DETECTED"
        color = "danger"
        emoji = "🔴"
        message = "This WhatsApp chat contains multiple scam indicators! Do not send money or click links."
        recommendations = [
            "🚨 BLOCK the sender immediately",
            "📞 Report the number to your service provider (333 for Safaricom, 3333 for Airtel)",
            "🚫 Never send money or share personal information",
            "📸 Take screenshots as evidence before blocking"
        ]
    elif score >= 25:
        risk_level = "MEDIUM RISK"
        color = "warning"
        emoji = "🟡"
        message = "This chat has suspicious elements. Verify before taking any action."
        recommendations = [
            "⚠️ Be very cautious with this conversation",
            "🔍 Verify the sender's identity through another channel",
            "🚫 Don't share any personal or financial information",
            "📞 Call the person directly to verify if it's really them"
        ]
    else:
        risk_level = "LOW RISK"
        color = "success"
        emoji = "🟢"
        message = "No obvious scam patterns detected, but always be cautious."
        recommendations = [
            "✅ Stay vigilant even with seemingly safe messages",
            "🔐 Never share your M-PESA PIN or OTP with anyone",
            "📱 Report any suspicious activity to your service provider"
        ]
    
    return {
        'score': score,
        'risk_level': risk_level,
        'color': color,
        'emoji': emoji,
        'message': message,
        'warnings': warnings if warnings else ["✅ No scam indicators found"],
        'recommendations': recommendations,
        'suspicious_messages': suspicious_messages[:3],
        'message_count': len(lines),
        'unique_senders': len(unique_senders),
        'type': 'WHATSAPP'
    }