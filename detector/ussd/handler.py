# detector/ussd/handler.py
"""
USSD Handler for AI Fraud Shield
Supports English and Swahili
Shortcode: *384# (example - can be changed)
"""

import re
from datetime import datetime
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

# User session storage (in production, use Redis or database)
ussd_sessions = {}


class USSDHandler:
    """Handle USSD requests and return responses"""
    
    def __init__(self, request):
        self.session_id = request.POST.get('sessionId', '')
        self.phone_number = request.POST.get('phoneNumber', '')
        self.service_code = request.POST.get('serviceCode', '*384#')
        self.text = request.POST.get('text', '').strip()
        
        # Parse USSD input levels
        self.inputs = self.text.split('*') if self.text else ['']
        self.current_level = len(self.inputs)
        
        # Initialize or retrieve session
        if self.session_id not in ussd_sessions:
            ussd_sessions[self.session_id] = {
                'phone': self.phone_number,
                'language': 'en',  # Default: English
                'step': 'main_menu',
                'data': {}
            }
        self.session = ussd_sessions[self.session_id]
        self.session['phone'] = self.phone_number
        
    def process(self):
        """Main USSD processing logic"""
        try:
            # Level 0: No input - Main Menu
            if not self.text:
                return self.show_language_menu()
            
            inputs = self.inputs
            level = len(inputs)
            user_input = inputs[-1]
            
            # Language selection (Level 1)
            if level == 1:
                return self.handle_language_selection(user_input)
            
            # Main Menu (Level 2)
            elif level == 2:
                return self.handle_main_menu(user_input)
            
            # Sub-menus (Level 3+)
            elif level >= 3:
                return self.handle_sub_menu(inputs, level, user_input)
            
            return self.end_session("Invalid input. Please try again.")
            
        except Exception as e:
            print(f"❌ USSD Process Error: {e}")
            import traceback
            traceback.print_exc()
            return self.end_session("Technical error. Please try again later.")
    
    def show_language_menu(self):
        """Show language selection menu"""
        menu = """CON Welcome to AI Fraud Shield 🛡️

Choose language / Chagua lugha:
1. English
2. Kiswahili

0. Exit"""
        return HttpResponse(menu, content_type='text/plain')
    
    def handle_language_selection(self, choice):
        """Handle language selection"""
        if choice == '1':
            self.session['language'] = 'en'
            return self.show_main_menu()
        elif choice == '2':
            self.session['language'] = 'sw'
            return self.show_main_menu()
        elif choice == '0':
            del ussd_sessions[self.session_id]
            return self.end_session("Thank you for using AI Fraud Shield. Stay safe!")
        else:
            return self.show_language_menu()
    
    def show_main_menu(self):
        """Display main menu in selected language"""
        if self.session['language'] == 'en':
            menu = """CON 🛡️ AI Fraud Shield - Main Menu

1. Report a Scam 📞
2. Check Scam Number 🔍
3. Subscribe to Alerts 🔔
4. Safety Tips 💡
5. Report Fake M-Pesa Receipt 📸
6. Emergency Contacts 🚨
7. Scam Statistics 📊

0. Exit

Reply with number:"""
        else:
            menu = """CON 🛡️ AI Fraud Shield - Menu Kuu

1. Ripoti Utapeli 📞
2. Angalia Namba ya Utapeli 🔍
3. Jiandikishe kwa Tahadhari 🔔
4. Vidokezo vya Usalama 💡
5. Ripoti Risiti Bandia ya M-Pesa 📸
6. Nambari za Dharura 🚨
7. Takwimu za Utapeli 📊

0. Toka

Jibu kwa namba:"""
        
        return HttpResponse(menu, content_type='text/plain')
    
    def handle_main_menu(self, choice):
        """Handle main menu selection"""
        
        # Exit
        if choice == '0':
            del ussd_sessions[self.session_id]
            return self.end_session("Thank you for using AI Fraud Shield. Stay safe!")
        
        # Report a Scam
        if choice == '1':
            self.session['step'] = 'report_scam_type'
            return self.show_scam_types()
        
        # Check Scam Number
        elif choice == '2':
            self.session['step'] = 'check_number'
            if self.session['language'] == 'en':
                return self.prompt_response("Enter the phone number to check:\n(e.g., 0712345678)")
            else:
                return self.prompt_response("Ingiza namba ya simu kuangalia:\n(kwa mfano, 0712345678)")
        
        # Subscribe to Alerts
        elif choice == '3':
            self.session['step'] = 'subscribe_confirm'
            if self.session['language'] == 'en':
                return self.prompt_response(f"Subscribe to scam alerts?\n\nPhone: {self.phone_number}\n\n1. Yes\n2. No")
            else:
                return self.prompt_response(f"Je, ungependa kupokea tahadhari za utapeli?\n\nSimu: {self.phone_number}\n\n1. Ndiyo\n2. Hapana")
        
        # Safety Tips
        elif choice == '4':
            return self.show_safety_tips()
        
        # Report Fake M-Pesa Receipt
        elif choice == '5':
            self.session['step'] = 'report_receipt'
            if self.session['language'] == 'en':
                return self.prompt_response("Enter the amount shown on the receipt:\n(e.g., 5000)")
            else:
                return self.prompt_response("Ingiza kiasi kilichoonyeshwa kwenye risiti:\n(kwa mfano, 5000)")
        
        # Emergency Contacts
        elif choice == '6':
            return self.show_emergency_contacts()
        
        # Scam Statistics
        elif choice == '7':
            return self.show_scam_statistics()
        
        # Invalid
        else:
            return self.show_main_menu()
    
    def show_scam_types(self):
        """Show scam type selection"""
        if self.session['language'] == 'en':
            menu = """CON Select scam type:

1. SMS Scam
2. Phone Call Scam
3. WhatsApp Scam
4. Email Phishing
5. Fake M-Pesa Receipt
6. Fake Loan Offer
7. Prize/Lottery Scam
8. Other

0. Back"""
        else:
            menu = """CON Chagua aina ya utapeli:

1. Utapeli wa SMS
2. Utapeli wa Simu
3. Utapeli wa WhatsApp
4. Utapeli wa Barua Pepe
5. Risiti Bandia ya M-Pesa
6. Ofa Bandia ya Mkopo
7. Utapeli wa Zawadi
8. Nyingine

0. Nyuma"""
        
        return HttpResponse(menu, content_type='text/plain')
    
    def handle_sub_menu(self, inputs, level, user_input):
        """Handle deeper menu levels"""
        
        # Report Scam flow
        if self.session.get('step') == 'report_scam_type':
            self.session['scam_type'] = user_input
            self.session['step'] = 'report_scam_enter'
            
            if self.session['language'] == 'en':
                return self.prompt_response("Enter the scam message or describe what happened:\n(Max 160 characters)")
            else:
                return self.prompt_response("Ingiza ujumbe wa utapeli au eleza kilichotokea:\n(Hadithi 160)")
        
        elif self.session.get('step') == 'report_scam_enter':
            if user_input == '0':
                return self.show_main_menu()
            
            result = self.save_scam_report(user_input)
            
            if self.session['language'] == 'en':
                return self.end_session(f"✅ Scam report submitted!\n\nReference: {result['ref']}\nRisk Score: {result['score']}/100\n\nThank you for helping protect Kenyans!")
            else:
                return self.end_session(f"✅ Ripoti ya utapeli imetumwa!\n\nRejea: {result['ref']}\nAlama ya Hatari: {result['score']}/100\n\nAsante kwa kusaidia kulinda Wakenya!")
        
        # Check Number flow
        elif self.session.get('step') == 'check_number':
            if user_input == '0':
                return self.show_main_menu()
            
            result = self.check_number(user_input)
            
            if self.session['language'] == 'en':
                if result['is_scam']:
                    return self.end_session(f"🚨 SCAM NUMBER!\n\nPhone: {result['phone']}\nReports: {result['reports']}\nRisk: {result['risk']}%\n\nDO NOT engage with this number!")
                else:
                    return self.end_session(f"✅ Number appears safe\n\nPhone: {result['phone']}\nReports: {result['reports']}\nRisk: {result['risk']}%\n\nStill be cautious with unknown numbers.")
            else:
                if result['is_scam']:
                    return self.end_session(f"🚨 NAMBA YA UTAPELI!\n\nSimu: {result['phone']}\nRipoti: {result['reports']}\nHatari: {result['risk']}%\n\nUSIJISHUGHULISHE na namba hii!")
                else:
                    return self.end_session(f"✅ Namba inaonekana salama\n\nSimu: {result['phone']}\nRipoti: {result['reports']}\nHatari: {result['risk']}%\n\nKuwa mwangalifu na namba zisizojulikana.")
        
        # Subscribe flow
        elif self.session.get('step') == 'subscribe_confirm':
            if user_input == '1':
                self.subscribe_user()
                if self.session['language'] == 'en':
                    return self.end_session("✅ Subscribed! You will receive scam alerts via SMS.\n\nTo unsubscribe, dial *384# and select Unsubscribe.")
                else:
                    return self.end_session("✅ Umesajiliwa! Utapokea tahadhari za utapeli kwa SMS.\n\nIli kujiondoa, piga *384# na uchague Ondoa Ushiriki.")
            else:
                return self.show_main_menu()
        
        # Report receipt flow
        elif self.session.get('step') == 'report_receipt':
            if user_input == '0':
                return self.show_main_menu()
            
            self.session['receipt_amount'] = user_input
            self.session['step'] = 'report_receipt_number'
            
            if self.session['language'] == 'en':
                return self.prompt_response("Enter the sender's phone number:\n(e.g., 0712345678)")
            else:
                return self.prompt_response("Ingiza namba ya simu ya mtumaji:\n(kwa mfano, 0712345678)")
        
        elif self.session.get('step') == 'report_receipt_number':
            if user_input == '0':
                return self.show_main_menu()
            
            self.session['receipt_sender'] = user_input
            self.save_fake_receipt_report()
            
            if self.session['language'] == 'en':
                return self.end_session(f"✅ Fake receipt reported!\n\nAmount: Ksh {self.session['receipt_amount']}\nSender: {self.session['receipt_sender']}\n\nDO NOT release goods or money based on this receipt!")
            else:
                return self.end_session(f"✅ Risiti bandia imeripotiwa!\n\nKiasi: Ksh {self.session['receipt_amount']}\nMtumaji: {self.session['receipt_sender']}\n\nUSITOLE bidhaa au pesa kwa kutumia risiti hii!")
        
        # Fallback
        else:
            return self.show_main_menu()
    
    def show_safety_tips(self):
        """Display safety tips"""
        if self.session['language'] == 'en':
            tips = """END 🛡️ SAFETY TIPS:

1. NEVER share your M-Pesa PIN
2. NEVER share OTP codes
3. Verify caller's identity before sending money
4. Official companies never ask for PIN via SMS
5. HANG UP and call back official numbers
6. Report suspicious numbers to 333 (Safaricom)

📞 For help: SMS 333 or call 0800 722 203

Stay vigilant!"""
        else:
            tips = """END 🛡️ VIDOKEZO VYA USALAMA:

1. USITOE PIN yako ya M-Pesa
2. USITOE namba za OTP
3. Thibitisha utambulisho kabla ya kutuma pesa
4. Makampuni rasmi hayaombi PIN kwa SMS
5. KATA SIMU na piga namba rasmi
6. Ripoti namba za tuhuma kwa 333 (Safaricom)

📞 Msaada: SMS 333 au piga 0800 722 203

Kuwa mwangalifu!"""
        
        return HttpResponse(tips, content_type='text/plain')
    
    def show_emergency_contacts(self):
        """Display emergency contacts"""
        if self.session['language'] == 'en':
            contacts = """END 🚨 EMERGENCY CONTACTS:

Safaricom Fraud: 333
Airtel Fraud: 3333
DCI Hotline: 0800 722 203
Cybercrime: report@kenyacic.go.ke
Police: 999 or 112

Report immediately if scammed!"""
        else:
            contacts = """END 🚨 NAMBARI ZA DHARURA:

Utapeli Safaricom: 333
Utapeli Airtel: 3333
DCI Hotline: 0800 722 203
Utapeli wa Mtandao: report@kenyacic.go.ke
Polisi: 999 au 112

Ripoti mara moja ukiwa mtapeliwa!"""
        
        return HttpResponse(contacts, content_type='text/plain')
    
    def show_scam_statistics(self):
        """Display scam statistics"""
        try:
            from ..models import ScamReport
            from django.utils import timezone
            from datetime import timedelta
            from django.db import models
            
            # Get counts
            today = timezone.now().date()
            week_ago = today - timedelta(days=7)
            month_ago = today - timedelta(days=30)
            
            total_reports = ScamReport.objects.count()
            today_count = ScamReport.objects.filter(date_reported__date=today).count()
            week_count = ScamReport.objects.filter(date_reported__date__gte=week_ago).count()
            month_count = ScamReport.objects.filter(date_reported__date__gte=month_ago).count()
            
            # Get high risk count
            high_risk = ScamReport.objects.filter(risk_score__gte=70).count()
            
            # Get top scam type
            top_type = ScamReport.objects.values('report_type').annotate(
                count=models.Count('id')
            ).order_by('-count').first()
            
            if self.session['language'] == 'en':
                stats = """END 📊 SCAM STATISTICS

Total Reports: {total_reports}
Today: {today_count}
This Week: {week_count}
This Month: {month_count}
High Risk Scams: {high_risk}
Top Scam Type: {top_type['report_type'] if top_type else 'N/A'}

🛡️ Stay vigilant!
Report scams to help others."""
            else:
                stats = """END 📊 TAKWIMU ZA UTAPELI

Jumla ya Ripoti: {total_reports}
Leo: {today_count}
Wiki Hii: {week_count}
Mwezi Huu: {month_count}
Utapeli wa Hatari Kubwa: {high_risk}
Aina Kuu ya Utapeli: {top_type['report_type'] if top_type else 'N/A'}

🛡️ Kuwa mwangalifu!
Ripoti utapeli kusaidia wengine."""
            
            return HttpResponse(stats, content_type='text/plain')
            
        except Exception as e:
            print(f"Stats error: {e}")
            if self.session['language'] == 'en':
                return self.end_session("Unable to load statistics. Please try again later.")
            else:
                return self.end_session("Haiwezekani kupakia takwimu. Tafadhali jaribu tena baadaye.")
    
    def prompt_response(self, message):
        """Return a CON (continue) response"""
        return HttpResponse(f"CON {message}\n\n0. Back", content_type='text/plain')
    
    def end_session(self, message):
        """End USSD session"""
        # Clean up session
        if self.session_id in ussd_sessions:
            del ussd_sessions[self.session_id]
        return HttpResponse(f"END {message}", content_type='text/plain')
    
    # ============================================================
    # CORE FUNCTIONALITY METHODS
    # ============================================================
    
    def save_scam_report(self, description):
        """Save scam report to database with SMS confirmation and points"""
        try:
            from ..models import ScamReport, BlockedNumber
            from ..sms_detector import detect_sms_scam
            from django.utils import timezone
            import re
            
            # Analyze the report
            result = detect_sms_scam(description)
            risk_score = result.get('score', 50)
            
            # Extract phone number from description if present
            extracted_phone = None
            phone_match = re.search(r'(07|01|2547)\d{8}', description)
            if phone_match:
                extracted_phone = phone_match.group(0)
                # Clean the phone number
                if extracted_phone.startswith('0'):
                    extracted_phone = '254' + extracted_phone[1:]
                elif not extracted_phone.startswith('254'):
                    extracted_phone = '254' + extracted_phone[-9:]
            
            # Map scam type
            scam_type_map = {
                '1': 'SMS', '2': 'CALL', '3': 'WHATSAPP',
                '4': 'EMAIL', '5': 'SMS', '6': 'SMS',
                '7': 'SMS', '8': 'OTHER'
            }
            report_type = scam_type_map.get(self.session.get('scam_type', '1'), 'SMS')
            
            # Save to database
            report = ScamReport.objects.create(
                report_type=report_type,
                content=f"[USSD Report from {self.phone_number}]\nType: {self.session.get('scam_type')}\nPhone: {extracted_phone or 'N/A'}\n\n{description}"[:500],
                risk_score=risk_score,
                risk_level=result.get('risk_level_display', 'MEDIUM'),
                reported_by=self.phone_number,
                phone_number=extracted_phone if extracted_phone else None,
                date_reported=timezone.now(),
            )
            
            print(f"✅ USSD Report saved: {report.id} | Risk: {risk_score}%")
            
            # If a scam phone number was extracted, add to BlockedNumber
            if extracted_phone and risk_score >= 40:
                try:
                    blocked, created = BlockedNumber.objects.get_or_create(
                        phone_number=extracted_phone,
                        defaults={
                            'report_count': 1,
                            'scam_category': report_type,
                            'description': f"Reported via USSD by {self.phone_number}",
                            'reported_by': self.phone_number,
                            'confidence_score': risk_score,
                            'status': 'CONFIRMED' if risk_score >= 70 else 'SUSPICIOUS'
                        }
                    )
                    if not created:
                        blocked.report_count += 1
                        blocked.confidence_score = (blocked.confidence_score + risk_score) // 2
                        if risk_score >= 70:
                            blocked.status = 'CONFIRMED'
                        blocked.save()
                    print(f"✅ BlockedNumber updated: {extracted_phone}")
                except Exception as e:
                    print(f"⚠️ BlockedNumber error: {e}")
            
            return {
                'ref': f"USS{report.id}",
                'score': risk_score,
                'risk_level': result.get('risk_level_display', 'MEDIUM'),
                'extracted_phone': extracted_phone
            }
            
        except Exception as e:
            print(f"❌ Save scam report error: {e}")
            import traceback
            traceback.print_exc()
            return {'ref': 'ERR', 'score': 0, 'error': str(e)}
    
    def check_number(self, number):
        """Check if number is reported as scam"""
        try:
            from ..models import BlockedNumber
            
            cleaned = self.clean_phone_number(number)
            
            blocked = BlockedNumber.objects.filter(phone_number=cleaned).first()
            
            if blocked and blocked.status in ['CONFIRMED', 'BLOCKED']:
                return {
                    'is_scam': True,
                    'phone': cleaned,
                    'reports': blocked.report_count,
                    'risk': blocked.confidence_score
                }
            else:
                return {
                    'is_scam': False,
                    'phone': cleaned,
                    'reports': blocked.report_count if blocked else 0,
                    'risk': blocked.confidence_score if blocked else 0
                }
        except Exception as e:
            print(f"❌ Check number error: {e}")
            return {'is_scam': False, 'phone': number, 'reports': 0, 'risk': 0}
    
    def clean_phone_number(self, phone):
        """Clean and format phone number"""
        # Remove any non-digit characters
        phone = re.sub(r'\D', '', phone)
        
        # Format to 254
        if phone.startswith('0'):
            phone = '254' + phone[1:]
        elif phone.startswith('+254'):
            phone = phone[1:]
        elif not phone.startswith('254') and len(phone) == 9:
            phone = '254' + phone
        
        return phone
    
    def subscribe_user(self):
        """Subscribe user to scam alerts"""
        try:
            from django.contrib.auth.models import User
            from ..models import UserProfile
            
            # Try to find existing user
            user = User.objects.filter(username=self.phone_number).first()
            if not user:
                # Create new user
                user = User.objects.create_user(
                    username=self.phone_number,
                    password=self.phone_number + 'temp123'
                )
            
            # Update profile
            profile, created = UserProfile.objects.get_or_create(
                user=user,
                defaults={'phone_number': self.phone_number}
            )
            profile.ussd_subscribed = True
            profile.save()
            
            print(f"✅ Subscribed {self.phone_number} to USSD alerts")
        except Exception as e:
            print(f"❌ Subscribe error: {e}")
    
    def save_fake_receipt_report(self):
        """Save fake receipt report"""
        try:
            from ..models import ScamReport
            
            ScamReport.objects.create(
                report_type='SCREENSHOT',
                content=f"[FAKE RECEIPT REPORT via USSD]\nAmount: Ksh {self.session.get('receipt_amount')}\nSender: {self.session.get('receipt_sender')}\nReporter: {self.phone_number}",
                risk_score=85,
                risk_level='HIGH',
                reported_by=self.phone_number,
            )
            
            print(f"✅ Fake receipt report saved from {self.phone_number}")
        except Exception as e:
            print(f"❌ Save fake receipt error: {e}")


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
        print(f"❌ USSD Error: {e}")
        import traceback
        traceback.print_exc()
        return HttpResponse("END Service temporarily unavailable. Try again later.", content_type='text/plain')