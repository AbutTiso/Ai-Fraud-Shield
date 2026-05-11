
# run_telegram_bot.py - Simple Telegram Bot using raw API
import os
import sys
import json
import time
import requests

# Setup Django
sys.path.append(os.path.dirname(__file__))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fraudshield.settings')
import django
django.setup()

from django.conf import settings

# Get token
BOT_TOKEN = getattr(settings, 'TELEGRAM_BOT_TOKEN', 'YOUR_TOKEN_HERE')
BASE_URL = f'https://api.telegram.org/bot{BOT_TOKEN}'
OFFSET = 0

def send_message(chat_id, text, reply_markup=None):
    """Send message to Telegram chat"""
    url = f'{BASE_URL}/sendMessage'
    data = {
        'chat_id': chat_id,
        'text': text,
        'parse_mode': 'Markdown'
    }
    if reply_markup:
        data['reply_markup'] = json.dumps(reply_markup)
    
    try:
        resp = requests.post(url, json=data, timeout=10)
        return resp.json()
    except Exception as e:
        print(f"Send error: {e}")
        return None

def get_updates():
    """Get new messages from Telegram"""
    global OFFSET
    url = f'{BASE_URL}/getUpdates'
    params = {'offset': OFFSET, 'timeout': 30}
    
    try:
        resp = requests.get(url, params=params, timeout=35)
        data = resp.json()
        
        if data.get('ok') and data.get('result'):
            for update in data['result']:
                OFFSET = update['update_id'] + 1
                yield update
    except Exception as e:
        print(f"Polling error: {e}")

def analyze_scam(text):
    """Use Django's scam detection"""
    try:
        from detector.views import detect_sms_scam
        result = detect_sms_scam(text)
        score = result.get('score', 0)
        
        if score >= 70:
            return f"🚨🔴 *SCAM DETECTED!*\nScore: {score}/100\n\nDO NOT respond or send money!"
        elif score >= 40:
            return f"⚠️🟡 *SUSPICIOUS*\nScore: {score}/100\n\nBe very careful with this message."
        else:
            return f"✅ *Appears Safe*\nScore: {score}/100\n\nNo scam indicators detected."
    except Exception as e:
        return f"❌ Error: {str(e)}"

def check_number_reputation(number):
    """Check number in blocklist"""
    cleaned = number.replace('-','').replace(' ','').replace('+','')
    if cleaned.startswith('0'): cleaned = '254' + cleaned[1:]
    
    try:
        from detector.models import BlockedNumber
        try:
            entry = BlockedNumber.objects.get(phone_number=cleaned)
            if entry.status in ['CONFIRMED','BLOCKED']:
                return f"🚨 *KNOWN SCAM NUMBER!*\n📞 {cleaned}\nReports: {entry.report_count}\nConfidence: {entry.confidence_score}%\n\nBLOCK THIS NUMBER!"
            else:
                return f"⚠️ *Reported Number*\n📞 {cleaned}\nReports: {entry.report_count}\nConfidence: {entry.confidence_score}%"
        except BlockedNumber.DoesNotExist:
            return f"✅ *Not in blocklist*\n📞 {cleaned}\n\nNo reports found."
    except Exception as e:
        return f"❌ Error: {str(e)}"

def report_number_to_db(number, user_id):
    """Report a scam number"""
    cleaned = number.replace('-','').replace(' ','').replace('+','')
    if cleaned.startswith('0'): cleaned = '254' + cleaned[1:]
    
    try:
        from detector.models import BlockedNumber
        entry, created = BlockedNumber.objects.get_or_create(
            phone_number=cleaned,
            defaults={'report_count': 1, 'reported_by': f'telegram:{user_id}'}
        )
        if not created:
            entry.report_count += 1
            entry.calculate_confidence()
            entry.save(update_fields=['report_count','confidence_score','status','last_reported'])
        return f"✅ *Reported!*\n📞 {cleaned}\nReports: {entry.report_count}\nConfidence: {round(entry.confidence_score,1)}%"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def process_message(msg):
    """Process a single message"""
    if 'message' not in msg:
        return
    
    message = msg['message']
    chat_id = message['chat']['id']
    text = message.get('text', '')
    user_id = message['from']['id']
    
    if not text:
        return
    
    print(f"📨 {message['from'].get('first_name','?')}: {text[:50]}")
    
    # Commands
    if text.startswith('/start'):
        send_message(chat_id,
            "🛡️ *AI Fraud Shield Bot*\n\n"
            "Send me a suspicious message to analyze\n"
            "Send a phone number to check its reputation\n"
            "/report [number] - Report scam number\n"
            "/stats - View statistics\n"
            "/help - Show commands"
        )
    
    elif text.startswith('/help'):
        send_message(chat_id,
            "📋 *Commands:*\n"
            "/start - Welcome\n"
            "/check [msg] - Analyze message\n"
            "/number [phone] - Check number\n"
            "/report [number] - Report scam\n"
            "/stats - Statistics"
        )
    
    elif text.startswith('/check'):
        msg_text = text.replace('/check','',1).strip()
        if msg_text:
            reply = analyze_scam(msg_text)
            send_message(chat_id, reply)
        else:
            send_message(chat_id, "Please include a message to check. Example: `/check Your M-Pesa has been suspended`")
    
    elif text.startswith('/number'):
        number = text.replace('/number','',1).strip()
        if number:
            reply = check_number_reputation(number)
            send_message(chat_id, reply)
        else:
            send_message(chat_id, "Please include a number. Example: `/number 0712345678`")
    
    elif text.startswith('/report'):
        number = text.replace('/report','',1).strip()
        if number:
            reply = report_number_to_db(number, user_id)
            send_message(chat_id, reply)
        else:
            send_message(chat_id, "Please include a number. Example: `/report 0712345678`")
    
    elif text.startswith('/stats'):
        try:
            from detector.models import ScamReport, BlockedNumber
            from django.utils import timezone
            total = ScamReport.objects.count() if ScamReport.objects else 0
            today = ScamReport.objects.filter(date_reported__date=timezone.now().date()).count() if ScamReport.objects else 0
            blocked = BlockedNumber.objects.filter(status__in=['CONFIRMED','BLOCKED']).count()
            send_message(chat_id, f"📊 *Statistics*\n\nTotal Reports: {total:,}\nToday: {today}\nBlocked Numbers: {blocked}\n\n📞 Report: SMS *333*")
        except Exception as e:
            send_message(chat_id, f"Error: {e}")
    
    else:
        # Check if it's a phone number
        cleaned = text.replace('-','').replace(' ','').replace('+','')
        if cleaned.isdigit() and 9 <= len(cleaned) <= 13:
            reply = check_number_reputation(text)
        else:
            reply = analyze_scam(text)
        send_message(chat_id, reply)

def main():
    """Main loop"""
    print("🤖 Starting Telegram bot...")
    print("✅ Bot is running! Press Ctrl+C to stop.")
    
    # Test connection
    resp = requests.get(f'{BASE_URL}/getMe')
    if resp.json().get('ok'):
        bot_info = resp.json()['result']
        print(f"✅ Connected as @{bot_info['username']}")
    else:
        print("❌ Failed to connect. Check your token.")
        return
    
    while True:
        try:
            for update in get_updates():
                process_message(update)
        except KeyboardInterrupt:
            print("\n👋 Bot stopped.")
            break
        except Exception as e:
            print(f"Loop error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()