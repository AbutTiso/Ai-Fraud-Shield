# run_telegram_bot.py - Enhanced Telegram Bot with ML + Better Analysis
import os
import sys
import json
import time
import requests
import re

# Setup Django
sys.path.append(os.path.dirname(__file__))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fraudshield.settings')
import django
django.setup()

from django.conf import settings
from django.utils import timezone as django_timezone

# Get token
BOT_TOKEN = getattr(settings, 'TELEGRAM_BOT_TOKEN', 'YOUR_TOKEN_HERE')
BASE_URL = f'https://api.telegram.org/bot{BOT_TOKEN}'
OFFSET = 0

def send_message(chat_id, text, reply_markup=None, parse_mode='Markdown'):
    """Send message to Telegram chat"""
    url = f'{BASE_URL}/sendMessage'
    data = {
        'chat_id': chat_id,
        'text': text[:4096],  # Telegram limit
        'parse_mode': parse_mode,
        'disable_web_page_preview': True
    }
    if reply_markup:
        data['reply_markup'] = json.dumps(reply_markup)
    
    try:
        resp = requests.post(url, json=data, timeout=10)
        return resp.json()
    except Exception as e:
        print(f"Send error: {e}")
        return None

def send_typing(chat_id):
    """Show typing indicator"""
    url = f'{BASE_URL}/sendChatAction'
    requests.post(url, json={'chat_id': chat_id, 'action': 'typing'}, timeout=5)

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

def get_inline_keyboard(buttons):
    """Create inline keyboard markup"""
    return {"inline_keyboard": buttons}

def analyze_scam_detailed(text, user_id=None, user_name=None):
    """
    Enhanced scam analysis using both keyword detection and ML model
    Returns detailed analysis with warnings and recommendations
    Also saves to database for dashboard tracking
    """
    try:
        from detector.views import detect_sms_scam
        result = detect_sms_scam(text)
        score = result.get('score', 0)
        risk_level = result.get('risk_level', 'Unknown')
        warnings = result.get('warnings', [])
        recommendations = result.get('recommendations', [])
        indicators = result.get('indicators', {})
        
        # ============================================================
        # SAVE TO DATABASE FOR DASHBOARD
        # ============================================================
        try:
            from detector.models import ScamReport
            if ScamReport.objects:
                ScamReport.objects.create(
                    report_type='TELEGRAM',
                    content=text[:500],
                    risk_score=score,
                    risk_level=risk_level[:20] if risk_level else 'Unknown',
                    reported_by=f'telegram:{user_id}' if user_id else 'telegram:anonymous'
                )
                print(f"  💾 Dashboard updated - Score: {score}")
        except Exception as e:
            print(f"  ⚠️ Dashboard save error: {e}")
        
        # Try ML prediction for hybrid score
        ml_score = None
        try:
            from detector.ml.inference.predict import predict_scam
            ml_result = predict_scam(text)
            if ml_result:
                ml_score = ml_result.get('ml_score', 0)
        except:
            pass
        
        # Build response
        if score >= 70:
            emoji = "🚨🔴"
            verdict = "*CRITICAL - SCAM CONFIRMED!*"
            color = "danger"
        elif score >= 50:
            emoji = "⚠️🟠"
            verdict = "*HIGH RISK - Likely Scam*"
            color = "warning"
        elif score >= 30:
            emoji = "🔍🟡"
            verdict = "*SUSPICIOUS - Be Cautious*"
            color = "warning"
        elif score >= 10:
            emoji = "📝🔵"
            verdict = "*LOW RISK - Minor Concerns*"
            color = "info"
        else:
            emoji = "✅🟢"
            verdict = "*SAFE - No Scam Detected*"
            color = "success"
        
        response = f"{emoji} *AI Fraud Shield Analysis*\n\n"
        response += f"📊 *Risk Score:* {score}/100\n"
        response += f"📋 *Risk Level:* {risk_level}\n"
        response += f"💡 *Verdict:* {verdict}\n"
        
        if ml_score:
            response += f"🧠 *ML Score:* {ml_score}/100\n"
        
        # Add pattern indicators
        if indicators:
            high_risk = indicators.get('high_risk', [])
            medium_risk = indicators.get('medium_risk', [])
            url_count = indicators.get('url_count', 0)
            phone_count = indicators.get('phone_count', 0)
            grammar = indicators.get('grammar_issues', 0)
            
            details = []
            if url_count: details.append(f"🔗 URLs found: {url_count}")
            if phone_count: details.append(f"📞 Phone numbers: {phone_count}")
            if grammar: details.append(f"📝 Grammar issues: {grammar}")
            if high_risk: details.append(f"🚨 Critical indicators: {', '.join(high_risk[:3])}")
            
            if details:
                response += "\n📋 *Details:*\n"
                for d in details:
                    response += f"  • {d}\n"
        
        # Add top warnings
        if warnings:
            response += "\n⚠️ *Key Warnings:*\n"
            for w in warnings[:4]:
                response += f"  • {w}\n"
        
        # Add recommendations
        if recommendations:
            response += "\n✅ *What To Do:*\n"
            for r in recommendations[:3]:
                response += f"  • {r}\n"
        
        # Add safety footer
        if score >= 40:
            response += "\n━━━━━━━━━━━━━━\n"
            response += "🔒 *Never share:*\n"
            response += "  • M-Pesa PIN\n"
            response += "  • OTP codes\n"
            response += "  • Passwords\n"
            response += "  • Bank details\n"
        
        response += "\n🛡️ _Powered by AI Fraud Shield_"
        
        # Build keyboard
        keyboard = [
            [{"text": "📞 Report Scam", "callback_data": "report"},
             {"text": "📊 More Details", "callback_data": f"details_{score}"}],
            [{"text": "🛡️ Safety Tips", "callback_data": "tips"},
             {"text": "ℹ️ About", "callback_data": "about"}]
        ]
        
        return response, get_inline_keyboard(keyboard)
        
    except Exception as e:
        return f"❌ Analysis Error: {str(e)}\n\nPlease try again.", None
    
def check_number_reputation(number):
    """Enhanced number check with full blocklist integration"""
    cleaned = re.sub(r'\D', '', number)
    if cleaned.startswith('0') and len(cleaned) == 10:
        cleaned = '254' + cleaned[1:]
    elif not cleaned.startswith('254'):
        cleaned = '254' + cleaned[-9:]
    
    try:
        from detector.models import BlockedNumber
        
        try:
            entry = BlockedNumber.objects.get(phone_number=cleaned)
            
            # Determine status
            if entry.status in ['CONFIRMED', 'BLOCKED']:
                emoji = "🚨"
                status_text = "KNOWN SCAM NUMBER"
                action = "🚫 *BLOCK THIS NUMBER IMMEDIATELY!*"
            elif entry.confidence_score >= 60:
                emoji = "⚠️"
                status_text = "HIGH RISK - Multiple Reports"
                action = "⚠️ Strongly consider blocking this number"
            elif entry.confidence_score >= 30:
                emoji = "🔍"
                status_text = "SUSPICIOUS - Under Investigation"
                action = "⚠️ Exercise caution with this number"
            else:
                emoji = "📝"
                status_text = "LOW RISK - Few Reports"
                action = "Be aware but no immediate threat"
            
            response = """{emoji} *Number Reputation Check*

📞 *Number:* `{cleaned}`
📊 *Reports:* {entry.report_count}
📈 *Confidence:* {entry.confidence_score}%
📋 *Status:* {status_text}
🏷️ *Category:* {entry.scam_category or 'N/A'}
📅 *First Reported:* {entry.first_reported.strftime('%d %b %Y')}
📅 *Last Reported:* {entry.last_reported.strftime('%d %b %Y')}

{action}

👍 *Upvotes:* {entry.upvotes} | 👎 *Downvotes:* {entry.downvotes}"""
            
            keyboard = get_inline_keyboard([
                [{"text": "👍 Upvote", "callback_data": f"upvote_{cleaned}"},
                 {"text": "👎 Downvote", "callback_data": f"downvote_{cleaned}"}],
                [{"text": "📞 Report Again", "callback_data": f"report_{cleaned}"}]
            ])
            
            return response, keyboard
            
        except BlockedNumber.DoesNotExist:
            response = """✅ *Number Check - Clean*

📞 *Number:* `{cleaned}`
📊 *Status:* Not in scam database
✅ *Safe to interact?* No reports found

⚠️ *Always:*
• Verify unknown callers
• Never share PINs or passwords
• Report suspicious numbers

📞 Report scams: SMS *333* (Safaricom)"""
            
            keyboard = get_inline_keyboard([
                [{"text": "🚨 Report as Scam", "callback_data": f"report_{cleaned}"}]
            ])
            
            return response, keyboard
            
    except Exception as e:
        return f"❌ Error checking number: {str(e)}", None

def report_number_to_db(number, user_id, user_name=""):
    """Enhanced number reporting with feedback"""
    cleaned = re.sub(r'\D', '', number)
    if cleaned.startswith('0') and len(cleaned) == 10:
        cleaned = '254' + cleaned[1:]
    elif not cleaned.startswith('254'):
        cleaned = '254' + cleaned[-9:]
    
    try:
        from detector.models import BlockedNumber
        
        entry, created = BlockedNumber.objects.get_or_create(
            phone_number=cleaned,
            defaults={
                'report_count': 1,
                'reported_by': f'telegram:{user_id}',
                'upvotes': 1
            }
        )
        
        if not created:
            entry.report_count += 1
            entry.upvotes += 1
            entry.calculate_confidence()
            entry.save(update_fields=['report_count', 'upvotes', 'confidence_score', 'status', 'last_reported'])
        
        # Show different messages based on report count
        if entry.report_count == 1:
            badge = "🆕 First Report!"
        elif entry.report_count >= 10:
            badge = f"🔥 High Alert! {entry.report_count} reports"
        elif entry.report_count >= 5:
            badge = f"⚠️ Multiple Reports: {entry.report_count}"
        else:
            badge = f"📊 {entry.report_count} reports now"
        
        response = """✅ *Report Submitted!*

📞 *Number:* `{cleaned}`
📊 *Total Reports:* {entry.report_count}
📈 *Confidence:* {round(entry.confidence_score, 1)}%
📋 *Status:* {entry.status}
{badge}

🙏 *Thank you for helping protect others!*
You've made Kenya safer! 🇰🇪

🛡️ _Powered by AI Fraud Shield_"""
        
        keyboard = get_inline_keyboard([
            [{"text": "📊 View Stats", "callback_data": "stats"},
             {"text": "🛡️ Safety Tips", "callback_data": "tips"}]
        ])
        
        return response, keyboard
        
    except Exception as e:
        return f"❌ Error: {str(e)}", None

def get_stats():
    """Get comprehensive statistics"""
    try:
        from detector.models import ScamReport, BlockedNumber
        from django.db.models import Count
        
        today = django_timezone.now().date()
        week_ago = today - django_timezone.timedelta(days=7)
        
        # Total stats
        total_reports = ScamReport.objects.count() if ScamReport.objects else 0
        today_count = ScamReport.objects.filter(date_reported__date=today).count() if ScamReport.objects else 0
        week_count = ScamReport.objects.filter(date_reported__date__gte=week_ago).count() if ScamReport.objects else 0
        
        # Blocklist stats
        blocked_count = BlockedNumber.objects.filter(status__in=['CONFIRMED', 'BLOCKED']).count()
        pending_count = BlockedNumber.objects.filter(status='PENDING').count()
        total_blocked = BlockedNumber.objects.count()
        
        # High risk reports
        high_risk = ScamReport.objects.filter(risk_score__gte=70).count() if ScamReport.objects else 0
        
        response = """📊 *AI Fraud Shield Statistics*

🛡️ *All Time:*
  • Total Reports: *{total_reports:,}*
  • High Risk Scams: *{high_risk:,}*

📅 *This Week:*
  • Reports: *{week_count:,}*
  • Today: *{today_count:,}*

🚫 *Blocklist:*
  • Blocked Numbers: *{blocked_count}*
  • Pending Review: *{pending_count}*
  • Total Tracked: *{total_blocked}*

📞 *Report scams:*
  • Safaricom: SMS *333*
  • Airtel: SMS *3333*
  • Our Bot: /report [number]

🛡️ _Stay vigilant! Never share PINs or passwords._"""
        
        keyboard = get_inline_keyboard([
            [{"text": "🚨 Report Number", "callback_data": "report"},
             {"text": "🛡️ Safety Tips", "callback_data": "tips"}]
        ])
        
        return response, keyboard
        
    except Exception as e:
        return f"❌ Error loading stats: {str(e)}", None

def get_safety_tips():
    """Get safety tips"""
    tips = """🛡️ *Scam Prevention Tips*

🚫 *NEVER share:*
• M-Pesa PIN / MPIN
• OTP verification codes
• Online banking passwords
• ATM card details

📞 *Phone Scams:*
• Don't trust caller ID - numbers can be spoofed
• Hang up on threats about account closure
• Call official numbers back yourself

📱 *SMS/WhatsApp Scams:*
• Don't click suspicious links
• Verify "won prize" messages
• Check sender carefully

💰 *Money Scams:*
• No legitimate company asks for fees to release loans
• "Double your money" is always a scam
• Verify M-Pesa transactions yourself

📞 *Report to:*
• Safaricom: *333*
• Airtel: *3333*
• Our bot: /report [number]

🛡️ _Stay safe out there!_"""
    
    keyboard = get_inline_keyboard([
        [{"text": "🔍 Check Message", "callback_data": "check_msg"},
         {"text": "📞 Check Number", "callback_data": "check_num"}]
    ])
    
    return tips, keyboard

def handle_callback(callback_query):
    """Handle inline button callbacks"""
    query_id = callback_query['id']
    data = callback_query.get('data', '')
    chat_id = callback_query['message']['chat']['id']
    message_id = callback_query['message']['message_id']
    
    # Answer callback to remove loading
    requests.post(f'{BASE_URL}/answerCallbackQuery', 
                  json={'callback_query_id': query_id}, timeout=5)
    
    if data == 'stats':
        stats_text, keyboard = get_stats()
        edit_message(chat_id, message_id, stats_text, keyboard)
    
    elif data == 'tips':
        tips_text, keyboard = get_safety_tips()
        edit_message(chat_id, message_id, tips_text, keyboard)
    
    elif data == 'about':
        about_text = """🛡️ *AI Fraud Shield*

*Made in Kenya 🇰🇪*
Protecting Kenyans from scams using AI.

*Features:*
• SMS & WhatsApp scam detection
• Phone number reputation check
• URL safety checker
• Real-time call monitoring
• Crowdsourced blocklist

🌐 *Website:* fraudshield.ke
📞 *Report:* SMS 333"""
        edit_message(chat_id, message_id, about_text)
    
    elif data == 'check_msg':
        send_message(chat_id, "📝 Send me any suspicious message and I'll analyze it for scams!")
    
    elif data == 'check_num':
        send_message(chat_id, "📞 Send me a phone number to check its reputation!\nExample: `0712345678`")
    
    elif data == 'report':
        send_message(chat_id, "🚨 Send the scam number to report!\nFormat: `/report 0712345678`")
    
    elif data.startswith('report_'):
        number = data.replace('report_', '')
        response, keyboard = report_number_to_db(number, callback_query['from']['id'], callback_query['from'].get('first_name', ''))
        edit_message(chat_id, message_id, response, keyboard)
    
    elif data.startswith('upvote_'):
        number = data.replace('upvote_', '')
        try:
            from detector.models import BlockedNumber
            entry = BlockedNumber.objects.get(phone_number=number)
            entry.upvotes += 1
            entry.calculate_confidence()
            entry.save(update_fields=['upvotes', 'confidence_score'])
            response, keyboard = check_number_reputation(number)
            edit_message(chat_id, message_id, response, keyboard)
        except:
            pass
    
    elif data.startswith('downvote_'):
        number = data.replace('downvote_', '')
        try:
            from detector.models import BlockedNumber
            entry = BlockedNumber.objects.get(phone_number=number)
            entry.downvotes += 1
            entry.save(update_fields=['downvotes'])
            response, keyboard = check_number_reputation(number)
            edit_message(chat_id, message_id, response, keyboard)
        except:
            pass
    
    elif data.startswith('details_'):
        send_message(chat_id, "📊 Full analysis details are shown above with the risk score and recommendations.")

def edit_message(chat_id, message_id, text, reply_markup=None):
    """Edit an existing message"""
    url = f'{BASE_URL}/editMessageText'
    data = {
        'chat_id': chat_id,
        'message_id': message_id,
        'text': text[:4096],
        'parse_mode': 'Markdown',
        'disable_web_page_preview': True
    }
    if reply_markup:
        data['reply_markup'] = json.dumps(reply_markup)
    
    try:
        requests.post(url, json=data, timeout=10)
    except Exception as e:
        print(f"Edit error: {e}")

def process_message(msg):
    """Process a single message with enhanced features"""
    if 'message' not in msg and 'callback_query' not in msg:
        return
    
    # Handle callback queries (button presses)
    if 'callback_query' in msg:
        handle_callback(msg['callback_query'])
        return
    
    message = msg['message']
    chat_id = message['chat']['id']
    text = message.get('text', '')
    user_id = message['from']['id']
    user_name = message['from'].get('first_name', 'User')
    
    if not text:
        return
    
    print(f"📨 {user_name}: {text[:60]}")
    
    # Show typing indicator
    send_typing(chat_id)
    time.sleep(0.5)  # Brief pause for natural feel
    
    # Commands
    if text.startswith('/start'):
        response = """🛡️ *Welcome, {user_name}!*

I'm the *AI Fraud Shield Bot* 🇰🇪

*What I can do:*
📱 *Check Messages* - Send any suspicious SMS/email
📞 *Check Numbers* - Verify phone number reputation  
🚨 *Report Scams* - Help protect others
📊 *Statistics* - View scam data
💡 *Safety Tips* - Learn to spot scams

*Quick Start:*
• Just send me a suspicious message
• Or send a phone number to check
• Use buttons below to navigate 👇"""

        keyboard = get_inline_keyboard([
            [{"text": "🔍 Check Message", "callback_data": "check_msg"},
             {"text": "📞 Check Number", "callback_data": "check_num"}],
            [{"text": "🚨 Report Scam", "callback_data": "report"},
             {"text": "📊 Stats", "callback_data": "stats"}],
            [{"text": "🛡️ Safety Tips", "callback_data": "tips"},
             {"text": "ℹ️ About", "callback_data": "about"}]
        ])
        
        send_message(chat_id, response, keyboard)
    
    elif text.startswith('/help'):
        response = """📋 *Available Commands*

*Main Features:*
/start - Welcome & menu
/check [msg] - Detailed scam analysis
/number [phone] - Check number reputation
/report [number] - Report scam number
/stats - View statistics
/tips - Safety tips
/about - About AI Fraud Shield

*Quick:*
Just send any message for instant analysis!
Send a phone number for reputation check."""

        keyboard = get_inline_keyboard([
            [{"text": "🔍 Check Message", "callback_data": "check_msg"},
             {"text": "📞 Check Number", "callback_data": "check_num"}],
            [{"text": "📊 Stats", "callback_data": "stats"}]
        ])
        
        send_message(chat_id, response, keyboard)
    
    elif text.startswith('/check'):
        msg_text = text.replace('/check', '', 1).strip()
        if msg_text:
            response, keyboard = analyze_scam_detailed(msg_text)
            send_message(chat_id, response, keyboard)
        else:
            send_message(chat_id, "📝 *Please include a message to check.*\n\nExample: `/check Your M-Pesa has been suspended. Send PIN to verify!`")
    
    elif text.startswith('/number'):
        number = text.replace('/number', '', 1).strip()
        if number:
            response, keyboard = check_number_reputation(number)
            send_message(chat_id, response, keyboard)
        else:
            send_message(chat_id, "📞 *Please include a phone number.*\n\nExample: `/number 0712345678`")
    
    elif text.startswith('/report'):
        number = text.replace('/report', '', 1).strip()
        if number:
            response, keyboard = report_number_to_db(number, user_id, user_name)
            send_message(chat_id, response, keyboard)
        else:
            send_message(chat_id, "🚨 *Please include a number to report.*\n\nExample: `/report 0712345678`")
    
    elif text.startswith('/stats'):
        response, keyboard = get_stats()
        send_message(chat_id, response, keyboard)
    
    elif text.startswith('/tips'):
        response, keyboard = get_safety_tips()
        send_message(chat_id, response, keyboard)
    
    elif text.startswith('/about'):
        response = """🛡️ *AI Fraud Shield*

*Made in Kenya 🇰🇪*
Protecting Kenyans from scams using advanced AI.

*Our Mission:*
To make Kenya the safest digital space in Africa by detecting and preventing scams before they harm you.

*Features:*
📱 SMS/WhatsApp scam detection
📞 Phone number reputation check
🔗 URL safety checker
🎙️ Real-time call monitoring
👥 Crowdsourced blocklist
🤖 Telegram & WhatsApp bots

*Impact:*
✅ Thousands of scams detected
✅ Growing blocklist database
✅ Community-driven protection

🌐 fraudshield.ke"""
        
        keyboard = get_inline_keyboard([
            [{"text": "📊 Stats", "callback_data": "stats"},
             {"text": "🛡️ Tips", "callback_data": "tips"}]
        ])
        
        send_message(chat_id, response, keyboard)
    
    else:
        # Auto-detect: phone number or message
        cleaned = re.sub(r'\D', '', text)
        if cleaned.isdigit() and 9 <= len(cleaned) <= 13:
            response, keyboard = check_number_reputation(text)
        else:
            response, keyboard = analyze_scam_detailed(text, user_id, user_name)
        send_message(chat_id, response, keyboard)

def main():
    """Main loop"""
    print("🤖 Starting AI Fraud Shield Telegram Bot...")
    print("=" * 50)
    
    # Test connection
    resp = requests.get(f'{BASE_URL}/getMe')
    if resp.json().get('ok'):
        bot_info = resp.json()['result']
        print(f"✅ Connected as @{bot_info['username']}")
        print(f"✅ Bot ID: {bot_info['id']}")
        print(f"✅ Bot Name: {bot_info['first_name']}")
    else:
        print("❌ Failed to connect. Check your token in settings.py")
        return
    
    print("=" * 50)
    print("📋 Available Features:")
    print("  • Message scam analysis")
    print("  • Phone number reputation check")
    print("  • Scam reporting with blocklist integration")
    print("  • Statistics dashboard")
    print("  • Inline keyboard navigation")
    print("  • ML-enhanced detection")
    print("=" * 50)
    print("✅ Bot is running! Press Ctrl+C to stop.")
    print("📱 Open Telegram and send /start to @AIFraudShield_Bot")
    print()
    
    while True:
        try:
            for update in get_updates():
                process_message(update)
        except KeyboardInterrupt:
            print("\n👋 Bot stopped. Stay safe!")
            break
        except Exception as e:
            print(f"⚠️ Loop error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()