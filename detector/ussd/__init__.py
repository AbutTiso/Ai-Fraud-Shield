# detector/ussd/handler.py
import re
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

class USSDHandler:
    """Handle USSD requests and return responses"""
    
    def __init__(self, request):
        self.session_id = request.POST.get('sessionId', '')
        self.phone_number = request.POST.get('phoneNumber', '')
        self.service_code = request.POST.get('serviceCode', '*483*72#')
        self.text = request.POST.get('text', '').strip()
        
        # Parse USSD input levels
        self.inputs = self.text.split('*') if self.text else ['']
        self.current_level = len(self.inputs)
        
    def process(self):
        """Main USSD processing logic"""
        # Level 1: Main Menu
        if self.current_level == 1 or not self.text:
            return self.main_menu()
        
        # Level 2: Handle menu selection
        elif self.current_level == 2:
            choice = self.inputs[0]
            if choice == '1':
                return self.report_scam_prompt()
            elif choice == '2':
                return self.check_number_prompt()
            elif choice == '3':
                return self.recent_alerts()
            elif choice == '4':
                return self.safety_tips()
            else:
                return self.main_menu()
        
        # Level 3: Process input
        elif self.current_level == 3:
            choice = self.inputs[0]
            user_input = self.inputs[2] if len(self.inputs) > 2 else self.inputs[1]
            
            if choice == '1':
                return self.report_scam_number(user_input)
            elif choice == '2':
                return self.check_number(user_input)
            else:
                return self.main_menu()
        
        return self.end_session("Invalid input. Please try again.")
    
    def main_menu(self):
        """Display main menu"""
        menu = """CON AI Fraud Shield 🛡️
1. Report Scam Number
2. Check Number Safety
3. Recent Scam Alerts
4. Safety Tips
5. Exit"""
        return HttpResponse(menu, content_type='text/plain')
    
    def report_scam_prompt(self):
        """Prompt for scam number"""
        return HttpResponse("CON Report Scam Number\nEnter scam phone number (e.g., 0712345678):", content_type='text/plain')
    
    def report_scam_number(self, number):
        """Save reported scam number"""
        # Clean number
        cleaned = number.strip().replace('-', '').replace(' ', '')
        if not cleaned.isdigit() or len(cleaned) < 9:
            return HttpResponse("CON Invalid number!\nEnter valid phone number:", content_type='text/plain')
        
        # Format to 254
        if cleaned.startswith('0'):
            cleaned = '254' + cleaned[1:]
        elif not cleaned.startswith('254'):
            cleaned = '254' + cleaned[-9:]
        
        try:
            from detector.models import BlockedNumber
            
            number_obj, created = BlockedNumber.objects.get_or_create(
                phone_number=cleaned,
                defaults={
                    'report_count': 1,
                    'scam_category': 'Reported via USSD',
                    'description': f'Reported by {self.phone_number}',
                    'reported_by': self.phone_number
                }
            )
            
            if not created:
                number_obj.report_count += 1
                number_obj.calculate_confidence()
                number_obj.save()
            
            return self.end_session(f"✅ Number {cleaned} reported!\nThank you for helping protect others.\n🛡️ AI Fraud Shield")
        except Exception as e:
            return self.end_session("❌ Error reporting number. Try again later.")
    
    def check_number_prompt(self):
        """Prompt for number to check"""
        return HttpResponse("CON Check Number Safety\nEnter phone number:", content_type='text/plain')
    
    def check_number(self, number):
        """Check if number is in blocklist"""
        cleaned = number.strip().replace('-', '').replace(' ', '')
        if not cleaned.isdigit():
            return HttpResponse("CON Invalid number!\nEnter valid number:", content_type='text/plain')
        
        if cleaned.startswith('0'):
            cleaned = '254' + cleaned[1:]
        
        try:
            from detector.models import BlockedNumber
            num = BlockedNumber.objects.filter(phone_number=cleaned).first()
            
            if num and num.status in ['CONFIRMED', 'BLOCKED']:
                return self.end_session(f"🚨 SCAM NUMBER!\n{cleaned}\nReports: {num.report_count}\nConfidence: {num.confidence_score}%\n\nDO NOT trust this number!")
            elif num:
                return self.end_session(f"⚠️ SUSPICIOUS\n{cleaned}\nReports: {num.report_count}\n\nBe careful with this number.")
            else:
                return self.end_session(f"✅ NOT REPORTED\n{cleaned}\nNo scam reports found.\n\nAlways verify unknown callers.")
        except:
            return self.end_session("❌ Error checking number.")
    
    def recent_alerts(self):
        """Show recent scam alerts"""
        try:
            from detector.models import ScamReport
            recent = ScamReport.objects.filter(risk_score__gte=70).order_by('-date_reported')[:3]
            
            if not recent:
                return self.end_session("No recent scam alerts.\nStay vigilant!")
            
            alert_text = "Recent Scam Alerts:\n"
            for i, r in enumerate(recent, 1):
                alert_text += f"{i}. {r.report_type}: {r.content[:40]}...\n"
            
            return self.end_session(alert_text + "🛡️ AI Fraud Shield")
        except:
            return self.end_session("Could not load alerts.")
    
    def safety_tips(self):
        """Show safety tips"""
        tips = """Safety Tips:
1. NEVER share PIN/OTP
2. Verify unknown callers
3. Report scams to 333
4. Don't click links
🛡️ AI Fraud Shield"""
        return self.end_session(tips)
    
    def end_session(self, message):
        """End USSD session"""
        return HttpResponse(f"END {message}", content_type='text/plain')


@csrf_exempt
def ussd_callback(request):
    """Africa's Talking USSD callback endpoint"""
    try:
        handler = USSDHandler(request)
        response = handler.process()
        
        # Log the USSD session
        print(f"📱 USSD: {handler.phone_number} | Level: {handler.current_level} | Input: {handler.text}")
        
        return response
    except Exception as e:
        print(f"USSD Error: {e}")
        return HttpResponse("END Service temporarily unavailable. Try again later.", content_type='text/plain')