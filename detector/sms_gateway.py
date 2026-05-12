# detector/sms_gateway.py
import os
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
        print(f"✅ Africa's Talking initialized")
    else:
        AT_AVAILABLE = False
        print("⚠️ AT_API_KEY not set - SMS sending disabled")
except ImportError:
    AT_AVAILABLE = False
    print("⚠️ africastalking package not installed - SMS sending disabled")


def send_sms_reply(phone_number, message):
    """Send SMS reply to user who forwarded a scam message"""
    if not AT_AVAILABLE:
        print(f"[SIMULATED] SMS to {phone_number}: {message[:60]}...")
        return {"success": True, "simulated": True}
    
    try:
        response = sms.send(message, [phone_number])
        print(f"✅ SMS sent to {phone_number}")
        return {"success": True, "response": response}
    except Exception as e:
        print(f"❌ SMS failed: {e}")
        return {"success": False, "error": str(e)}


def build_reply(score, warnings):
    """Build SMS reply based on scam score"""
    if score >= 70:
        return f"🚨 SCAM! {score}/100. DO NOT respond/send money/share PIN. Report: 333. 🛡️ AI Fraud Shield"
    elif score >= 40:
        return f"⚠️ SUSPICIOUS! {score}/100. Verify through official channels. Call Safaricom on 100. 🛡️ AI Fraud Shield"
    else:
        return f"✅ Likely SAFE. {score}/100. Still verify if unexpected. 🛡️ AI Fraud Shield"


@csrf_exempt
@require_http_methods(["POST", "GET"])
def sms_webhook(request):
    """
    Africa's Talking incoming SMS webhook
    
    Receives forwarded scam SMS and auto-replies with analysis
    """
    # GET request - show service info
    if request.method == "GET":
        return JsonResponse({
            "service": "AI Fraud Shield SMS Gateway",
            "status": "active" if AT_AVAILABLE else "simulation",
            "instructions": "Forward suspicious SMS to our shortcode for instant analysis"
        })
    
    # POST request - process incoming SMS
    try:
        # Africa's Talking sends form data
        sender = request.POST.get('from', '')
        recipient = request.POST.get('to', '')
        message_text = request.POST.get('text', '')
        message_id = request.POST.get('id', '')
        
        print(f"\n📨 SMS RECEIVED:")
        print(f"   From: {sender}")
        print(f"   To: {recipient}")
        print(f"   Message: {message_text[:100]}")
        
        if not sender or not message_text:
            return JsonResponse({"error": "Missing sender or message"}, status=400)
        
        # Analyze the message
        from .views import detect_sms_scam
        result = detect_sms_scam(message_text)
        score = result.get('score', 0)
        warnings = result.get('warnings', [])
        
        print(f"   Score: {score}/100")
        
        # Build reply
        reply = build_reply(score, warnings)
        
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
                    risk_level='HIGH' if score >= 70 else ('MEDIUM' if score >= 40 else 'LOW'),
                    reported_by='sms_gateway'
                )
        except Exception as e:
            print(f"DB save error: {e}")
        
        return JsonResponse({
            "success": True,
            "score": score,
            "reply_sent": sms_result.get("success", False)
        })
        
    except Exception as e:
        print(f"❌ Webhook error: {e}")
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def send_sms_alert(request):
    """Send SMS alert to subscribed users"""
    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
        phone = data.get('phone', '')
        message = data.get('message', '')
        
        if not phone or not message:
            return JsonResponse({"error": "Phone and message required"}, status=400)
        
        result = send_sms_reply(phone, message)
        return JsonResponse(result)
        
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)