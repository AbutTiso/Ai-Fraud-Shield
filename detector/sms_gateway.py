# detector/sms_gateway.py
"""
SMS Gateway for AI Fraud Shield
Handles incoming SMS via Africa's Talking and sends auto-replies
"""

import os
import re
from datetime import datetime
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json

# Try to initialize Africa's Talking
try:
    import africastalking
    AT_USERNAME = getattr(settings, 'AT_USERNAME', os.getenv('AT_USERNAME', 'sandbox'))
    AT_API_KEY = getattr(settings, 'AT_API_KEY', os.getenv('AT_API_KEY', ''))
    
    if AT_API_KEY:
        africastalking.initialize(AT_USERNAME, AT_API_KEY)
        sms = africastalking.SMS
        AT_AVAILABLE = True
        print("✅ Africa's Talking initialized successfully")
    else:
        AT_AVAILABLE = False
        print("⚠️ AT_API_KEY not set - SMS sending disabled (simulation mode)")
except ImportError:
    AT_AVAILABLE = False
    print("⚠️ africastalking package not installed - SMS sending disabled (simulation mode)")
except Exception as e:
    AT_AVAILABLE = False
    print(f"⚠️ Africa's Talking initialization failed: {e}")


def send_sms_reply(phone_number, message):
    """
    Send SMS reply to user who forwarded a scam message
    
    Args:
        phone_number (str): Recipient phone number
        message (str): SMS message content (max 160 chars)
    
    Returns:
        dict: Result with success status
    """
    # Clean phone number (remove +, spaces, etc.)
    phone_number = re.sub(r'[^0-9]', '', phone_number)
    if phone_number.startswith('0'):
        phone_number = '254' + phone_number[1:]
    elif not phone_number.startswith('254'):
        phone_number = '254' + phone_number[-9:]
    
    # Truncate message to 160 chars
    if len(message) > 160:
        message = message[:157] + '...'
    
    if not AT_AVAILABLE:
        print(f"[SIMULATED] SMS to {phone_number}: {message}")
        return {"success": True, "simulated": True, "message": message}
    
    try:
        response = sms.send(message, [phone_number])
        print(f"✅ SMS sent to {phone_number}: {message[:50]}...")
        return {"success": True, "response": response, "simulated": False}
    except Exception as e:
        print(f"❌ SMS failed to {phone_number}: {e}")
        return {"success": False, "error": str(e), "simulated": False}


def build_reply(score, risk_level_display, warnings):
    """
    Build SMS reply based on scam score
    
    Args:
        score (int): Risk score 0-100
        risk_level_display (str): Risk level (CRITICAL/HIGH/MEDIUM/LOW)
        warnings (list): List of warning messages
    
    Returns:
        str: SMS reply message (max 160 chars)
    """
    if score >= 75:
        return f"🚨 SCAM! Score:{score}/100. DO NOT respond/send money/share PIN. Report:333. AI Fraud Shield"
    elif score >= 60:
        return f"⚠️ SCAM! Score:{score}/100. Do not click links/send money. Verify via official channels. AI Fraud Shield"
    elif score >= 35:
        return f"⚠️ SUSPICIOUS! Score:{score}/100. Verify via official channels before acting. AI Fraud Shield"
    elif score >= 15:
        return f"🔵 CAUTION! Score:{score}/100. Message has suspicious elements. Be careful. AI Fraud Shield"
    else:
        return f"✅ Likely SAFE. Score:{score}/100. Still verify if unexpected. AI Fraud Shield"


def format_warnings_for_sms(warnings, max_warnings=2):
    """Format warnings for SMS (limited space)"""
    if not warnings:
        return ""
    
    # Remove emojis for SMS (to save space)
    clean_warnings = []
    for w in warnings[:max_warnings]:
        # Remove common emojis
        clean = re.sub(r'[^\w\s\.\-\(\)]', '', w)
        clean = clean.strip()
        if clean and len(clean) > 5:
            clean_warnings.append(clean[:40])
    
    if clean_warnings:
        return " " + "; ".join(clean_warnings)
    return ""


@csrf_exempt
@require_http_methods(["POST", "GET"])
def sms_webhook(request):
    """
    Africa's Talking incoming SMS webhook
    
    Receives forwarded scam SMS and auto-replies with analysis
    
    Expected POST parameters (from Africa's Talking):
        - from: Sender phone number
        - to: Recipient phone number (your shortcode)
        - text: SMS message content
        - id: Message ID (optional)
    """
    
    # GET request - show service info
    if request.method == "GET":
        return JsonResponse({
            "service": "AI Fraud Shield SMS Gateway",
            "version": "2.0",
            "status": "active" if AT_AVAILABLE else "simulation",
            "features": {
                "scam_detection": True,
                "auto_reply": True,
                "database_saving": True
            },
            "instructions": "Forward suspicious SMS to our shortcode for instant scam analysis",
            "supported_carriers": ["Safaricom", "Airtel", "Telkom"]
        })
    
    # POST request - process incoming SMS
    try:
        # Africa's Talking sends form data
        sender = request.POST.get('from', '')
        recipient = request.POST.get('to', '')
        message_text = request.POST.get('text', '')
        message_id = request.POST.get('id', '')
        
        print(f"\n{'='*50}")
        print(f"📨 SMS RECEIVED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*50}")
        print(f"   From: {sender}")
        print(f"   To: {recipient}")
        print(f"   ID: {message_id}")
        print(f"   Message: {message_text[:100]}{'...' if len(message_text) > 100 else ''}")
        
        # Validate required fields
        if not sender or not message_text:
            print(f"⚠️ Missing required fields: sender={sender}, text={bool(message_text)}")
            return JsonResponse({"error": "Missing sender or message"}, status=400)
        
        # Analyze the message using enhanced detector
        from .sms_detector import get_detector
        detector = get_detector()
        result = detector.detect_sms_scam(message_text)
        
        score = result.get('score', 0)
        risk_level = result.get('risk_level_display', 'LOW')
        warnings = result.get('warnings', [])
        is_scam = result.get('is_scam', False)
        
        print("\n📊 ANALYSIS RESULTS:")
        print(f"   Score: {score}/100")
        print(f"   Risk Level: {risk_level}")
        print(f"   Is Scam: {is_scam}")
        print(f"   Warnings: {len(warnings)}")
        if warnings:
            print(f"   First warning: {warnings[0][:80]}")
        
        # Build reply
        reply = build_reply(score, risk_level, warnings)
        warning_suffix = format_warnings_for_sms(warnings)
        if warning_suffix:
            reply = reply[:140] + warning_suffix
        
        print("\n📤 AUTO-REPLY:")
        print(f"   To: {sender}")
        print(f"   Message: {reply}")
        
        # Send auto-reply
        sms_result = send_sms_reply(sender, reply)
        
        # Save to database
        try:
            from .models import ScamReport
            if ScamReport.objects:
                ScamReport.objects.create(
                    report_type='SMS',
                    content=f"FROM: {sender} | {message_text[:400]}",
                    risk_score=score,
                    risk_level=risk_level,
                    reported_by='sms_gateway',
                    ip_address='gateway'
                )
                print(f"✅ Report saved to database (Score: {score})")
        except Exception as e:
            print(f"⚠️ Database save error: {e}")
        
        print("\n✅ Webhook processed successfully")
        print(f"{'='*50}\n")
        
        return JsonResponse({
            "success": True,
            "score": score,
            "risk_level": risk_level,
            "is_scam": is_scam,
            "reply_sent": sms_result.get("success", False),
            "reply_message": reply,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"❌ Webhook error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            "error": str(e),
            "success": False
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def send_sms_alert(request):
    """
    Send SMS alert to subscribed users (admin endpoint)
    
    Expected JSON:
        {
            "phone": "0712345678",
            "message": "Alert message here",
            "bulk": false (optional)
        }
    """
    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
        phone = data.get('phone', '')
        message = data.get('message', '')
        bulk = data.get('bulk', False)
        phone_list = data.get('phone_list', [])
        
        if not message:
            return JsonResponse({"error": "Message required"}, status=400)
        
        # Single SMS
        if not bulk and phone:
            result = send_sms_reply(phone, message)
            return JsonResponse({
                "success": result.get("success", False),
                "type": "single",
                "recipient": phone,
                "message": message[:50] + "...",
                "simulated": result.get("simulated", False)
            })
        
        # Bulk SMS
        elif bulk and phone_list:
            results = []
            success_count = 0
            for p in phone_list[:100]:  # Limit to 100 per request
                result = send_sms_reply(p, message)
                results.append({
                    "phone": p,
                    "success": result.get("success", False)
                })
                if result.get("success"):
                    success_count += 1
            
            return JsonResponse({
                "success": True,
                "type": "bulk",
                "total": len(phone_list),
                "successful": success_count,
                "failed": len(phone_list) - success_count,
                "results": results[:10]  # Return first 10 results
            })
        
        else:
            return JsonResponse({"error": "Phone number required for single SMS or phone_list for bulk"}, status=400)
        
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def gateway_stats(request):
    """Get SMS gateway statistics"""
    try:
        from .models import ScamReport
        sms_reports = ScamReport.objects.filter(report_type='SMS', reported_by='sms_gateway')
        
        return JsonResponse({
            "success": True,
            "stats": {
                "total_sms_processed": sms_reports.count(),
                "high_risk_detected": sms_reports.filter(risk_score__gte=60).count(),
                "medium_risk_detected": sms_reports.filter(risk_score__range=(35, 59)).count(),
                "low_risk_detected": sms_reports.filter(risk_score__lt=35).count(),
                "at_available": AT_AVAILABLE
            },
            "status": "active" if AT_AVAILABLE else "simulation"
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)