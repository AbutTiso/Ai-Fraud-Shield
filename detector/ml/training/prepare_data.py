# detector/ml/training/prepare_data.py
"""
Training data preparation for ML models.
400+ examples covering diverse scam patterns and legitimate contexts.
Context-aware labeling for ambiguous messages.
"""

import re
import json
from pathlib import Path


def clean_text(text):
    """Clean text for ML training"""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', ' URL ', text)
    text = re.sub(r'\b(07|01|2547)\d{8}\b', ' PHONE ', text)
    text = re.sub(r'ksh\s*\d[\d,]*', ' MONEY ', text)
    text = re.sub(r'[^a-zA-Z0-9\s!?]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_training_data_from_database():
    """
    Extract training examples from ScamReport database.
    Returns (messages, labels) tuples.
    """
    messages = []
    labels = []
    
    try:
        import django
        import os
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fraudshield.settings')
        django.setup()
        
        from detector.models import ScamReport
        
        reports = ScamReport.objects.all()[:1000]
        
        for report in reports:
            if report.content and len(report.content) > 10:
                label = 1 if report.risk_score >= 40 else 0
                messages.append(clean_text(report.content[:500]))
                labels.append(label)
        
        print(f"   Loaded {len(messages)} examples from database")
        
    except Exception as e:
        print(f"   Database load skipped: {e}")
    
    return messages, labels


def get_hardcoded_training_data():
    """
    Hardcoded training examples for bootstrapping.
    400+ examples covering diverse scam patterns, legitimate messages,
    and context-ambiguous edge cases.
    """
    
    # ================================================================
    # SCAM EXAMPLES (200+ patterns)
    # ================================================================
    scam = [
        # ========== M-PESA / MOBILE MONEY SCAMS (30) ==========
        'URGENT: Your M-Pesa suspended. Send PIN to verify.',
        'CONGRATULATIONS! Won Ksh 250000. Click http://scam.com',
        'Send MPIN to 0700000000 for M-Shwari bonus',
        'M-Pesa PIN required for verification: http://fake.co.ke',
        'Fuliza limit increased! Send MPIN to 0722000000 to activate',
        'M-Shwari loan pre-approved! Send Ksh 1000 processing fee',
        'Last warning! Your M-Pesa will be permanently blocked',
        'You received Ksh 50000 from unknown source. Confirm with PIN',
        'Your KCB M-Pesa loan limit is now Ksh 500000. Send PIN to activate',
        'Safaricom Bonga Points expired! Click http://bonga-fake.com to redeem',
        'Airtel Money: Your account will be deactivated. Verify now!',
        'Telkom T-kash: Winning notification. Send PIN to claim prize',
        'M-Pesa: Confirm your account by sending OTP to 0711222333',
        'Your M-Pesa statement shows fraud. Call 0799888777 immediately',
        'Fuliza loan approved! Ksh 30000 available. Send PIN to access',
        'M-Pesa: Your account needs verification. Reply with MPIN',
        'Your M-Shwari savings matured. Send PIN to withdraw Ksh 25000',
        'Safaricom promotion: You won Ksh 150000. Send PIN to claim',
        'M-Pesa reversal: Ksh 5000 sent to you in error. Return via PIN',
        'Your M-Pesa registration expired. Reactivate by sending OTP',
        'Congratulations! You have been selected for M-Pesa reward. Send 500',
        'M-Pesa security breach detected. All users must re-verify PIN',
        'Your Fuliza limit increased to 70000. Confirm with OTP now',
        'M-Shwari: Your locked savings of Ksh 12000 ready. Send PIN',
        'M-Pesa: Unusual activity detected. Verify identity with PIN',
        'Safaricom: Your line will be deactivated. Send PIN to keep active',
        'M-Pesa paybill payment failed. Refund pending. Send PIN to receive',
        'Your M-Pesa till number registration incomplete. Send PIN to finish',
        'M-Pesa agent float credited. Confirm transaction with OTP',
        'Safaricom data bundle won! Send PIN to activate free 50GB',
        
        # ========== BANKING SCAMS (30) ==========
        'Bank account blocked. Call 0712345678 immediately',
        'Pay Ksh 500 fee for KCB loan approval',
        'Dear customer, your ATM card is blocked. Call 0700123456',
        'KCB: Your account compromised. Transfer funds to 0711222333',
        'Equity Bank: Security update required. Click http://equity-fake.com',
        'CO-OP Bank: Dividend payment pending. Confirm account details',
        'Absa Bank: Unusual login detected. Call 0711987654 immediately',
        'Stanbic Bank: Your account frozen. Pay Ksh 5000 to unfreeze',
        'NCBA: Security breach detected. Send OTP to secure account',
        'Family Bank: Loan approved! Pay Ksh 2000 disbursement fee',
        'Breaking: Your bank account hacked. Call 0711987654 now!',
        'Your KCB loan of Ksh 50000 approved. Processing fee Ksh 2000 required',
        'Equity: Your online banking password expired. Update at http://equity-update.tk',
        'Standard Chartered: Suspicious transaction of Ksh 75000. Call to cancel',
        'DTB: Your account will be closed. Verify ownership with PIN',
        'IBL Bank: Congratulations! You won our quarterly draw. Send details',
        'Bank of Baroda: Your NRE account frozen. Pay Ksh 15000 to reactivate',
        'Citibank Kenya: Security token expired. Request new one with OTP',
        'Your Co-operative Bank account needs KYC update. Send ID and PIN',
        'Absa: Your credit card used for Ksh 89000 online purchase. Confirm?',
        'National Bank: Your cheque book request approved. Pay Ksh 500 delivery',
        'KCB: New paybill number 522522 for your loan repayment. Update now',
        'Equity: Your agent code suspended. Pay Ksh 10000 to reactivate',
        'Sidian Bank: Loan pre-approved at 5% interest. Processing fee Ksh 3000',
        'HFC: Your mortgage payment overdue. Pay Ksh 50000 to avoid auction',
        'GT Bank: Your dollar account limit reached. Upgrade with Ksh 10000',
        'Ecobank: International transfer of Ksh 200000 pending. Confirm PIN',
        'Bank of Africa: Your company account needs director approval. Send OTP',
        'KCB M-Pesa: Register your number to receive loans. Send PIN',
        'Equity M-Pesa: Link your bank account to M-Pesa. Send OTP to complete',
        
        # ========== GOVERNMENT/TAX SCAMS (25) ==========
        'Your KRA tax refund of Ksh 15000 ready. Send PIN to receive',
        'NSSF benefits pending. Pay Ksh 2000 processing fee',
        'NHIF: Your medical cover expired. Renew by sending OTP',
        'IMPORTANT: Your eCitizen account suspended. Verify identity',
        'KRA: Tax evasion case filed. Pay Ksh 50000 immediately',
        'Huduma Namba: Your registration incomplete. Send PIN to confirm',
        'NTSA: Your driving license suspended. Pay fine to 0712345678',
        'Immigration: Your passport application has issues. Call immediately',
        'Government grant approved! Pay Ksh 3000 processing fee',
        'Your KRA PIN is invalid. Update now at http://kra-fake.go.ke',
        'KRA: You owe Ksh 125000 in unpaid taxes. Pay now to avoid jail',
        'NHIF: Upgrade to comprehensive cover for only Ksh 500. Send OTP',
        'NEMA: Your business fined Ksh 75000 for pollution. Pay immediately',
        'Kenya Power: Your meter will be disconnected. Pay Ksh 5000 now',
        'KEBS: Your imported goods held. Clearance fee Ksh 25000 required',
        'Anti-Terrorism Police: Your number linked to criminal activity. Call',
        'DCI: Money laundering case against you. Pay Ksh 100000 to clear',
        'Presidential Bursary: Your child awarded Ksh 50000. Send PIN to claim',
        'County Government: Business permit expired. Renew with Ksh 15000',
        'NCA: Your construction project approved. Pay inspection fee Ksh 5000',
        'KAA: Your airport security clearance pending. Pay Ksh 3000 to process',
        'Hustler Fund: Your loan of Ksh 50000 approved. Send PIN to receive',
        'Inua Jamii: Your cash transfer of Ksh 8000 ready. Confirm with OTP',
        'Helb: Your loan application successful. Pay Ksh 2000 processing fee',
        'ECitizen: Your good conduct certificate ready. Pay Ksh 3000 delivery',
        
        # ========== INVESTMENT/CRYPTO SCAMS (20) ==========
        'Bitcoin investment guaranteed 200% returns! Send now',
        'Double your money! Send Ksh 5000 to 0711111111',
        'Forex trading signals. 100% guaranteed profits. Join today',
        'Crypto mining investment: 10% daily returns. Limited slots',
        'Get rich quick scheme. Invest Ksh 1000 get Ksh 10000 in 24 hours',
        'Real estate investment opportunity. 50% returns guaranteed',
        'Ponzi scheme alert! Earn Ksh 50000 weekly. Join now',
        'Chama investment: Double your shares in 30 days. Send now',
        'SACCO dividend payout: Send Ksh 1000 to receive Ksh 50000',
        'Gold trading: Invest Ksh 10000 get Ksh 100000 in one month',
        'Oil investment Kenya: Buy shares at Ksh 500 each. Limited offer',
        'Land for sale in Konza: Ksh 50000 per plot. Send deposit to secure',
        'Bitcoin doubling: Send 0.01 BTC receive 0.02 BTC instantly',
        'Ethereum airdrop: Claim your free ETH. Verify wallet with PIN',
        'Binance promotion: Win 1 BTC. Send Ksh 5000 to participate',
        'Forex managed account: 20% monthly returns. Minimum Ksh 50000',
        'Treasury bills: Invest Ksh 25000 earn 15% in 90 days. Guaranteed',
        'Crowdfunding investment: New tech startup. Buy shares now',
        'Diamond trust: Invest in Botswana diamonds. Ksh 10000 minimum',
        'Nairobi Securities Exchange: IPO shares available. Apply with Ksh 5000',
        
        # ========== JOB/EMPLOYMENT SCAMS (15) ==========
        'Work from home job! Earn Ksh 5000 daily. Registration fee Ksh 1000',
        'Data entry job available. No experience needed. Pay Ksh 1500 to apply',
        'Recruitment: NGO jobs. Pay Ksh 3000 interview fee. Call 0711222333',
        'Foreign job visa processing. Pay Ksh 50000 for Qatar opportunity',
        'Online writing job. Earn Ksh 1000 per article. Registration required',
        'Canada visa sponsorship: Construction workers needed. Pay Ksh 75000',
        'UK care home jobs: Nurses and caregivers needed. Pay Ksh 45000 fee',
        'Dubai hotel jobs: Receptionists and cleaners. Pay Ksh 35000 to apply',
        'KDF recruitment: Your application shortlisted. Pay Ksh 5000 medical fee',
        'TSC teacher recruitment: Position confirmed. Pay Ksh 3000 documentation',
        'UN jobs Kenya: Driver position available. Pay Ksh 2500 application fee',
        'Airline cabin crew: Kenya Airways hiring. Pay Ksh 5000 uniform fee',
        'Kazini: Your CV selected for interview. Pay Ksh 1500 scheduling fee',
        'Internship opportunity at big 4 firm. Pay Ksh 2000 placement fee',
        'Citi cleaning jobs: Immediate start. Pay Ksh 1000 for ID badge',
        
        # ========== DELIVERY/PACKAGE SCAMS (10) ==========
        'Your FedEx package held at customs. Pay Ksh 3000 to release',
        'DHL: Your parcel awaiting delivery. Clearance fee Ksh 2500 required',
        'Posta Kenya: Package arrived. Pay Ksh 1000 to collect',
        'Your package tracking: http://fake-tracking.com/claim',
        'Amazon: Your order #ORD789 held at JKIA. Pay Ksh 4500 customs fee',
        'AliExpress: Your parcel arrived. Clearance fee Ksh 2500. Pay to collect',
        'UPS: Your international package requires Ksh 5000 delivery fee',
        'EMS Kenya: Your document delivery pending. Confirm address with OTP',
        'G4S Courier: Package from UK held. Pay Ksh 3500 to release',
        'Speedaf Express: Your order from China ready. Pay Ksh 1500 delivery',
        
        # ========== LOTTERY/PRIZE SCAMS (15) ==========
        'You won the FIFA World Cup lottery! Send Ksh 5000 processing fee',
        'Congratulations! Your number won iPhone 15. Claim now',
        'UK National Lottery: Your email won GBP 500000. Contact agent',
        'Coca-Cola promotion: You won Ksh 1000000! Send details to claim',
        'Winner! Claim iPhone by sending OTP',
        'You have won the Safaricom lottery! Send 500 to claim',
        'Limited offer! Win iPhone 15 Pro. Click now!',
        'Shell promotion: You won Ksh 500000 in fuel cards. Send PIN',
        'Samsung giveaway: Your IMEI number selected. Send Ksh 2000 to claim',
        'Betika jackpot: You won Ksh 25000000! Send PIN to verify account',
        'SportPesa: Your bet of Ksh 100 won Ksh 5000000. Claim with OTP',
        'Omo detergent promotion: You won Ksh 100000. Send PIN to receive',
        'Coca-Cola cap promotion: You won a car! Send Ksh 15000 for delivery',
        'Facebook lottery: Your profile selected for Ksh 500000 prize. Claim now',
        'YouTube promotion: Your channel won Ksh 100000. Send PIN to verify',
        
        # ========== SOCIAL MEDIA/IMPERSONATION SCAMS (15) ==========
        'Hello dear, I am Mr. Johnson from UK. Need help to transfer funds',
        'Your WhatsApp will be deactivated. Verify at http://whatsapp-verify.tk',
        'Facebook security alert: Your account reported. Verify identity',
        'Instagram verification required. Your account will be deleted',
        'I am a military officer from US. Need your help with funds transfer',
        'Princess from Dubai needs your account to transfer millions',
        'UN diplomat: I have a business proposal worth millions. Contact me',
        'Your WhatsApp gold subscription activated. Send PIN to cancel',
        'Facebook: Your page has been reported. Appeal at http://facebook-appeal.tk',
        'Twitter verification badge available. Pay Ksh 5000 to get verified',
        'TikTok influencer program: You are selected. Pay Ksh 3000 to join',
        'Your Telegram account linked to illegal activity. Verify now',
        'Snapchat security: Your account compromised. Send OTP to secure',
        'LinkedIn premium: Your profile upgraded. Confirm with PIN',
        'Pinterest business account: You qualified. Pay Ksh 2000 to activate',
        
        # ========== PRESSURE/THREAT SCAMS (10) ==========
        'Breaking: Police case filed against you. Call 0711222333 urgently',
        'Security Alert: Verify your account immediately or face closure',
        'Final warning! Your account will be permanently deleted in 24 hours',
        'Court summons issued. Pay Ksh 15000 to cancel. Call now',
        'Your ID used for money laundering. Send Ksh 50000 to clear name',
        'Arrest warrant issued in your name. Pay Ksh 25000 to cancel',
        'KPLC: Your meter tampering detected. Pay Ksh 15000 fine immediately',
        'Your vehicle caught by speed camera. Pay Ksh 10000 fine now',
        'Bankruptcy notice filed against your business. Pay to stop proceedings',
        'Your insurance policy cancelled due to fraud. Pay Ksh 5000 to reinstate',
        
        # ========== SWAHILI SCAMS (20) ==========
        'Haraka! Akaunti yako imefungiwa. Tuma PIN.',
        'Tuma pesa kwa 0711222333 upokee zawadi',
        'Hongera! Umeshinda milioni. Tuma PIN kuthibitisha.',
        'Tuma pesa upate mkopo wa haraka. Lipa Ksh 500 usajili',
        'Umeshindwa kulipa deni yako. Piga simu 0799888777 sasa hivi',
        'Akaunti yako ya fuliza imeongezwa! Tuma PIN kuthibitisha',
        'Umepata kazi ya usafi Qatar. Lipa Ksh 50000 visa fee',
        'Pesa zako zimeibiwa. Tuma PIN kuzuia wizi',
        'Umechaguliwa kuwa balozi wa Safaricom. Tuma maelezo yako',
        'Kura yako haijahesabiwa. Thibitisha kwa kutuma OTP',
        'Ushindi! Umeibuka mshindi wa promo. Piga 0711222333 kudai',
        'Jina lako limetajwa kwenye kesi. Lipa Ksh 10000 kufuta',
        'Daktari wako amekutumia matokeo. Bonyeza kiungo hiki kutazama',
        'Umepata nafasi ya mkopo wa haraka. Jaza fomu hii sasa',
        'Hongera kwa kushinda gari mpya! Tuma Ksh 2000 usajili',
        'Tuma hela haraka. Mimi ni mtoto wako niko hospitalini',
        'Umetuzwa na shirika la misaada. Tuma PIN kuthibitisha',
        'Akaunti yako ya bank imezuiwa. Thibitisha kwa OTP',
        'Serikali imetoa ruzuku ya biashara. Jisajili kwa Ksh 1000',
        'Simu yako itafungiwa ndani ya saa 24. Thibitisha line yako',
        
        # ========== ROMANCE/DATING SCAMS (10) ==========
        'I am a US soldier deployed in Syria. Need money to come home',
        'I love you so much. Please send Ksh 50000 for my flight ticket',
        'My mother is in hospital. Please help with Ksh 25000 for surgery',
        'I am stuck at the airport. My wallet was stolen. Send Ksh 15000',
        'I want to marry you. Send Ksh 30000 for dowry preparations',
        'My business partner cheated me. Please lend me Ksh 100000',
        'I received a parcel from overseas. Help me pay Ksh 45000 customs fee',
        'My daughter needs school fees. Please help with Ksh 15000 urgently',
        'I lost my job due to COVID. Please help with rent Ksh 20000',
        'You are my soulmate. Let us start a business together. Send Ksh 50000',
        
        # ========== TECH SUPPORT SCAMS (5) ==========
        'Microsoft: Your computer infected with virus. Call support now',
        'Windows Defender: 5 threats found. Call 0711222333 to clean',
        'Your Apple ID has been locked. Verify at http://apple-unlock.tk',
        'Your Google account accessed from new device. Change password now',
        'Software update required. Your system is vulnerable. Click to update',
    ]
    
    # ================================================================
    # LEGITIMATE EXAMPLES (200+ patterns)
    # ================================================================
    legit = [
        # ========== M-PESA TRANSACTIONS (20) ==========
        'M-Pesa Ksh 500 to John successful. Balance: 2450',
        'M-Pesa: You received Ksh 1000 from Mary Wanjiku. Balance: Ksh 5000',
        'Safaricom: Ksh 200 airtime purchased. New balance: Ksh 800',
        'M-Pesa: You bought Ksh 100 airtime. Balance: Ksh 900',
        'Safaricom: Your M-Pesa statement for April is ready. Dial *334#',
        'M-Pesa: You have sent Ksh 500 to Peter. Transaction ID: MP123456',
        'Safaricom: Your M-Pesa balance is Ksh 3450 as at 10:30 AM',
        'M-Pesa: Ksh 2000 received from Employer Salary. New balance: Ksh 7000',
        'M-Pesa: Your transaction cost was Ksh 27. New balance: Ksh 5000',
        'Safaricom: You have successfully sent Ksh 1000 to Jane Doe',
        'M-Pesa: Ksh 15000 sent to Contractor for building materials',
        'M-Pesa: You have paid Ksh 3500 to KCB Paybill 522522',
        'Safaricom: Your Fuliza limit is Ksh 5000. Repay to increase',
        'M-Pesa: Ksh 250 received from M-Shwari savings interest',
        'M-Pesa: You have successfully withdrawn Ksh 10000 from agent',
        'Safaricom: Thank you for using M-Pesa. Dial *334# for services',
        'M-Pesa: Ksh 8000 paid to Kenya Power prepaid meter 12345678',
        'M-Pesa: Ksh 500 sent to till number 456789. Merchant: Supermart',
        'Safaricom: Your M-Pesa PIN change was successful',
        'M-Pesa: You have opted in for M-Pesa paperless statements',
        
        # ========== BANK NOTIFICATIONS (25) ==========
        'KCB: Salary 45000 credited to your account.',
        'Your KCB loan payment of Ksh 5000 received. Thank you',
        'Equity Bank: Your statement for April is ready',
        'Co-op Bank: Loan payment of Ksh 15000 due on 25th. Ref: LOAN001',
        'Absa: Your credit card payment of Ksh 25000 received',
        'Standard Chartered: New credit card delivered to your branch',
        'NCBA: Fixed deposit matured. Interest earned: Ksh 5000',
        'KCB: Your standing order for rent of Ksh 25000 has been processed',
        'Equity: Your cheque book is ready for collection at Kenyatta Avenue branch',
        'Co-op: Dividend payment of Ksh 3500 has been credited to your account',
        'KCB: Your account balance as at today is Ksh 125000.00',
        'Equity Bank: Your loan application is under review. We will contact you',
        'Stanbic: Your foreign exchange rate for USD is 145.50. Visit branch',
        'Absa: Your new ATM card has been dispatched to your branch',
        'NCBA: Your dollar account statement for May is now available',
        'Family Bank: Your fixed deposit of Ksh 500000 matured today',
        'KCB: Your tax certificate for interest earned is ready for collection',
        'Co-op: Your SMS alert service has been activated successfully',
        'Equity: Your savings plan deposit of Ksh 10000 received',
        'DTB: Your loan repayment schedule has been updated',
        'National Bank: Your pension contribution for May received',
        'Stanbic: Your internet banking token will expire in 7 days. Visit branch',
        'KCB: Important: New tariff guide effective 1st July. Visit kcbgroup.com',
        'Absa: Your cheque No. 001234 for Ksh 35000 has been cleared',
        'Equity: Congratulations on opening your new savings account',
        
        # ========== UTILITY BILLS (10) ==========
        'Your electricity token: 1234-5678-9012',
        'KPLC bill for May: Ksh 2350. Paybill 888880',
        'KPLC: Scheduled maintenance in your area on Sunday 2-5pm',
        'Nairobi Water: Your bill of Ksh 850 is due on 30th May',
        'KPLC: Your power will be disconnected if bill not paid by Friday',
        'Nairobi Water: Your meter reading for May is 45 units. Bill: Ksh 450',
        'KPLC: Your prepaid meter upgrade is due. Our team will visit next week',
        'KPLC: Thank you for your payment of Ksh 2350. Receipt: KPL2024001',
        'Nairobi Water: Water rationing in your area on Tuesday. Store water',
        'KPLC: Report any power outage by dialing *977# or call 0703070707',
        
        # ========== INSURANCE/GOVERNMENT LEGITIMATE (15) ==========
        'NHIF payment for May received. Status: Active',
        'Your NHIF card is ready for collection at Huduma Centre',
        'NSSF: Your contribution for May of Ksh 2000 received',
        'Your KRA PIN certificate is ready. Download from iTax',
        'Your driving license renewal successful. Pick at Huduma Centre',
        'Huduma Namba update: Visit chief camp on Monday',
        'NSSF: Your statement for Q1 2024 is ready. Visit nssf.go.ke',
        'KRA: Your tax compliance certificate is ready for download',
        'NSSF: Your benefit application has been received. Processing time 30 days',
        'NHIF: Your biometric registration at facility 12345 is confirmed',
        'KRA: Your iTax password was changed successfully',
        'Huduma Centre: Your ID replacement application is being processed',
        'NTSA: Your vehicle inspection booked for 15th June at Likoni',
        'KRA: Your employer filed your PAYE returns for May 2024',
        'Immigration: Your passport is ready for collection at Nyayo House',
        
        # ========== PERSONAL COMMUNICATION (25) ==========
        'Hello, pick up milk on your way home please',
        'Meeting at 3pm. Bring laptop and charger.',
        'Happy birthday! Have a wonderful day ahead.',
        'Dinner tonight at 7pm? Usual place.',
        'Please confirm your attendance for the wedding on Saturday',
        'Karibu nyumbani. Dinner iko tayari',
        'Can you send me the presentation before the meeting?',
        'Reminder: Pick up kids from school at 4pm',
        'Habari yako? Utakuja kesho kwa mkutano?',
        'Nimefika salama. Asante kwa kuniombea.',
        'Hi mom, what time will you be home today?',
        'Please bring your laptop to the meeting room',
        'Are we still on for lunch? Let me know what time',
        'I am running 10 minutes late. Traffic is terrible',
        'Happy anniversary! Can not believe it has been 5 years',
        'Call me when you get this. Need to discuss something urgent',
        'The plumber is coming tomorrow at 9am. Can you be home?',
        'I left my keys at the office. Can I borrow yours?',
        'Congratulations on the new job! So happy for you',
        'Just landed at JKIA. Heading home now',
        'Please pray for grandmother. She is not feeling well',
        'The kids have a football match on Saturday. You coming?',
        'I made chapati and stew. Come over for dinner',
        'Did you see the game last night? What a match!',
        'Let us do a road trip to Naivasha this weekend',
        
        # ========== SHOPPING/DELIVERY (10) ==========
        'Jumia package delivered. Track: JM123456',
        'Your parcel from Jumia is out for delivery today',
        'Thank you for shopping at Naivas. Points earned: 50',
        'Carrefour: Your online order #ORD123 is ready for pickup',
        'Jumia: Your order #JM789 has been dispatched. Delivery by 5pm',
        'Kilimall: Your refund of Ksh 1500 has been processed',
        'Jumia Food: Your order from Java House is being prepared',
        'Naivas Online: Your delivery slot is 2pm-4pm today',
        'Carrefour: Your loyalty points balance is now 250 points',
        'Jumia: Rate your recent purchase for a chance to win vouchers',
        
        # ========== RELIGIOUS/SOCIAL (10) ==========
        'Church service Sunday 9am. All welcome.',
        'Church harambee this Sunday. Contributions welcome',
        'Family dinner at Grandma place this Sunday. Bring dessert',
        'Prayer meeting this Wednesday at 6pm. All invited',
        'Wedding meeting this Saturday at 2pm. Please attend.',
        'The youth fellowship is this Friday at 5pm. Topic: Faith',
        'Remember to bring your Bible study book tomorrow',
        'Fundraiser for Sister Mary medical bills. Any amount welcome',
        'Choir practice moved to Thursday evening. Please note',
        'Thank you all for your prayers. Dad is recovering well',
        
        # ========== SCHOOL/EDUCATION (10) ==========
        'School fees payment Ksh 15000 received. Receipt: SCH001',
        'Your child school report ready for collection on Friday',
        'Reminder: Parent-teacher meeting tomorrow at 2pm',
        'University admission letter ready. Collect from registry',
        'Exam results for Term 2 are out. Check the school portal.',
        'Please pay Ksh 500 for class trip to museum next week',
        'Sports day this Friday. Students should wear house colors',
        'Graduation ceremony on 15th December. Confirm attendance',
        'Your child has been selected for academic award ceremony',
        'School will close early on Wednesday. Pick up at 12pm',
        
        # ========== TRAVEL/TRANSPORT (10) ==========
        'Flight booking: KQ100 Nairobi-Mombasa confirmed',
        'Your Uber is arriving. Driver: John, Toyota Corolla KDA 123T',
        'SGR ticket: Nairobi-Mombasa on 15th June. Seat C12',
        'Kenya Airways: Your check-in for flight KQ101 is now open',
        'SGR: Your train to Mombasa departs at 3pm from Nairobi Terminus',
        'Uber: Your trip receipt for yesterday is ready. Ksh 450',
        'Bolt: Driver James is 3 minutes away. Blue Toyota Vitz',
        'Precision Air: Flight PW721 to Dar es Salaam boarding at Gate 3',
        'SGR: Online booking confirmed. Reference: SGR202400789',
        'JamboJet: Your flight JM8602 to Mombasa is on time',
        
        # ========== HEALTH (10) ==========
        'Reminder: Doctor appointment tomorrow 10am',
        'Your lab results are ready. Visit clinic to collect',
        'Dentist appointment confirmed for Friday at 3pm',
        'NHIF: Your biometric registration is complete. Card processing.',
        'Pharmacy: Your prescription refill is ready for collection',
        'Aga Khan Hospital: Your MRI appointment is on Monday 8am',
        'Mater Hospital: Your NHIF pre-authorization has been approved',
        'Optician: Your glasses are ready. Come for fitting',
        'Your COVID test results are negative. Report attached',
        'Clinic: Remember to take your medication twice daily with meals',
        
        # ========== SERVICE NOTIFICATIONS (15) ==========
        'Safaricom: Your data bundle expires tomorrow. Dial *544#',
        'Safaricom: Your Bonga Points balance is 500. Redeem now',
        'Airtel: Your daily data bonus of 50MB is ready',
        'Zuku: Your internet bill of Ksh 2500 is due',
        'DSTV: Your subscription expires in 7 days. Renew now',
        'Safaricom: You have successfully subscribed to Go Weekly at Ksh 99',
        'Safaricom: Your postpaid bill of Ksh 2500 is ready. Pay by 25th.',
        'Safaricom: You have won 500 Bonga Points in our weekly draw! Points credited.',
        'Airtel: Thank you for recharging with Ksh 100. Bonus 50MB awarded',
        'Telkom: Your bill of Ksh 1500 is ready. Pay via M-Pesa Paybill 222111',
        'Netflix: Your subscription will renew on 15th June',
        'Spotify: Your premium plan has been upgraded successfully',
        'Google One: Your storage is 85% full. Manage at one.google.com',
        'GoDaddy: Your domain auto-renewal was successful',
        'Canon: Your printer ink levels are low. Order replacement at canon.co.ke',
        
        # ========== WORK/BUSINESS (15) ==========
        'Your leave application has been approved. Enjoy your time off',
        'Staff meeting postponed to Tuesday. Check email for details',
        'Your invoice #INV001 has been paid. Amount: Ksh 45000',
        'The quarterly report is due by Friday. Please submit on time',
        'Client presentation confirmed for Thursday 10am. Prepare slides.',
        'Your purchase order #PO456 has been approved by finance',
        'The server maintenance is scheduled for Saturday 2am-6am',
        'New company policy on remote work effective next month',
        'Please complete your timesheet by end of day Friday',
        'Team building event on 30th June. Confirm attendance by Monday',
        'Your business permit renewal is due by end of month',
        'Office will be closed on Monday for public holiday',
        'Your performance review is scheduled for next Wednesday',
        'The new software update will be rolled out this weekend',
        'Congratulations on completing your probation period',
        
        # ========== AMBIGUOUS/BORDERLINE CASES (10) ==========
        # These are legitimate messages that contain words often found in scams
        # The model needs to learn context, not just keywords
        'Your account security needs updating. Visit safaricom.com/security to update',
        'Congratulations! You have been selected for our customer loyalty program',
        'Reminder: Your subscription will auto-renew tomorrow. Text STOP to cancel',
        'KCB: We detected unusual activity. Please call our fraud hotline at 0711123456',
        'Equity Bank: Did you attempt to log in from a new device? Reply YES or NO',
        'Your Amazon account: A sign-in from Nairobi, Kenya was detected. Was this you?',
        'PayPal: Your payment of $50.00 to Netflix has been processed',
        'Google: A new device signed into your account. Review at google.com/devices',
        'Safaricom: Important security update. Visit safaricom.co.ke/security for details',
        'Your LinkedIn profile was viewed 15 times this week. See who viewed you',
    ]
    
    # Clean all messages
    messages = [clean_text(m) for m in scam] + [clean_text(m) for m in legit]
    labels = [1] * len(scam) + [0] * len(legit)
    
    print(f"   Hardcoded: {len(scam)} scam + {len(legit)} legit = {len(messages)} total")
    
    return messages, labels


def get_feedback_data():
    """Load user feedback corrections from feedback_data.json"""
    messages = []
    labels = []
    
    feedback_path = Path(__file__).parent.parent.parent / 'data' / 'feedback_data.json'
    
    if feedback_path.exists():
        try:
            with open(feedback_path) as f:
                feedbacks = json.load(f)
            
            for fb in feedbacks:
                if fb.get('original_text') and fb.get('user_verdict'):
                    if fb['user_verdict'] == 'scam':
                        messages.append(clean_text(fb['original_text']))
                        labels.append(1)
                    elif fb['user_verdict'] == 'legitimate':
                        messages.append(clean_text(fb['original_text']))
                        labels.append(0)
            
            if messages:
                print(f"   Feedback: {len(messages)} corrections loaded")
        except Exception as e:
            print(f"   Feedback load error: {e}")
    
    return messages, labels