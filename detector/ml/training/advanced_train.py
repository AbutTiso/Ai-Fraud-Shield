# detector/ml/training/advanced_train.py
import os, joblib, json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report
import re

# ============================================================
# WHITELIST - Known legitimate domains, numbers, and patterns
# ============================================================
LEGITIMATE_DOMAINS = {
    'safaricom.com', 'safaricom.co.ke', 'airtel.co.ke', 'telkom.co.ke',
    'kcbgroup.com', 'kcb.co.ke', 'equitybank.co.ke', 'coopbank.co.ke',
    'absabank.co.ke', 'stanbicbank.co.ke', 'ncbagroup.com',
    'kra.go.ke', 'ecitizen.go.ke', 'nssf.go.ke', 'nhif.go.ke',
    'hudumakenya.go.ke', 'ntsa.go.ke', 'posta.co.ke',
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'whatsapp.com', 'telegram.org', 'jumia.co.ke', 'kilimall.co.ke',
}

LEGITIMATE_SHORTCODES = {
    '*334#', '*544#', '*100#', '*200#', '*456#', '*131#',
    '*144#', '*282#', '*444#', '*126#', '*188#',
}

LEGITIMATE_PHONE_PREFIXES = [
    '0722', '0721', '0720', '0723',  # Safaricom
    '0733', '0736', '0710',  # Airtel
    '0770', '0771', '0772',  # Telkom
    '0700', '0701', '0702', '0703', '0704', '0705', '0706', '0707', '0708', '0709',
]

# Known legitimate message patterns
LEGITIMATE_PATTERNS = [
    r'(?:your|your\s+)(?:salary|loan\s+payment|bill|statement|receipt)\s+(?:of\s+)?(?:ksh|kes)\s*\d+',
    r'(?:church|mosque|temple)\s+(?:service|prayer|meeting|harambee)',
    r'(?:parent|teacher|school)\s+(?:meeting|report|fees)',
    r'(?:doctor|dentist|clinic)\s+(?:appointment|reminder)',
    r'(?:flight|train|bus)\s+(?:booking|ticket|reservation)',
    r'(?:uber|bolt|taxi)\s+(?:arriving|driver|confirmed)',
    r'(?:jumia|kilimall|carrefour|naivas)\s+(?:order|delivery|package)',
]

def is_known_legitimate(text):
    """Check if message matches known legitimate patterns"""
    text_lower = text.lower()
    
    # Check legitimate shortcodes
    for code in LEGITIMATE_SHORTCODES:
        if code in text:
            return True
    
    # Check legitimate patterns
    for pattern in LEGITIMATE_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    
    # Check for official bank/corporate format
    if re.search(r'(?:kcb|equity|coop|absa|stanbic|ncba|standard\s+chartered)\s*:', text_lower):
        # Has official bank prefix - likely legitimate notification
        if not re.search(r'(?:urgent|verify|click|link|send\s+(?:money|pin|otp|mpin))', text_lower):
            return True
    
    return False

def clean_text(text):
    """Clean text for better ML performance"""
    text = text.lower()
    # Preserve URLs but normalize them
    text = re.sub(r'http\S+|www\S+', ' URL ', text)
    # Preserve phone numbers but normalize
    text = re.sub(r'\b(07|01|2547)\d{8}\b', ' PHONE ', text)
    # Normalize money amounts
    text = re.sub(r'ksh\s*\d[\d,]*', ' MONEY ', text)
    # Remove special chars but keep spaces
    text = re.sub(r'[^a-zA-Z0-9\s!?]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# ============================================================
# EXTENDED TRAINING DATA - 150+ Examples with Edge Cases
# ============================================================
scam = [
    # ========== CLEAR SCAMS ==========
    # English - Financial/M-Pesa scams
    'URGENT: Your M-Pesa suspended. Send PIN to verify.',
    'CONGRATULATIONS! Won Ksh 250000. Click http://scam.com',
    'Bank account blocked. Call 0712345678 immediately',
    'Send MPIN to 0700000000 for M-Shwari bonus',
    'Winner! Claim iPhone by sending OTP',
    'Pay Ksh 500 fee for KCB loan approval',
    'Password expired. Update: http://phish.net',
    'M-Pesa PIN required for verification: http://fake.co.ke',
    'Limited offer! Win iPhone 15 Pro. Click now!',
    'Dear customer, your ATM card is blocked. Call 0700123456',
    'You have won the Safaricom lottery! Send 500 to claim',
    'Your KRA tax refund of Ksh 15000 ready. Send PIN to receive',
    'KCB: Your account compromised. Transfer funds to 0711222333',
    'Fuliza limit increased! Send MPIN to 0722000000 to activate',
    'Equity Bank: Security update required. Click http://equity-fake.com',
    'NSSF benefits pending. Pay Ksh 2000 processing fee',
    'NHIF: Your medical cover expired. Renew by sending OTP',
    'CO-OP Bank: Dividend payment pending. Confirm account details',
    'Absa Bank: Unusual login detected. Call 0711987654 immediately',
    'M-Shwari loan pre-approved! Send Ksh 1000 processing fee',
    'Last warning! Your M-Pesa will be permanently blocked',
    'You received Ksh 50000 from unknown source. Confirm with PIN',
    'Breaking: Police case filed against you. Call 0711222333 urgently',
    'Stanbic Bank: Your account frozen. Pay Ksh 5000 to unfreeze',
    'NCBA: Security breach detected. Send OTP to secure account',
    'Family Bank: Loan approved! Pay Ksh 2000 disbursement fee',
    'Your KCB M-Pesa loan limit is now Ksh 500000. Send PIN to activate',
    'Safaricom Bonga Points expired! Click http://bonga-fake.com to redeem',
    'Airtel Money: Your account will be deactivated. Verify now!',
    'Telkom T-kash: Winning notification. Send PIN to claim prize',
    
    # ========== MORE SCAMS ==========
    # Investment/Crypto scams
    'Bitcoin investment guaranteed 200% returns! Send now',
    'Double your money! Send Ksh 5000 to 0711111111',
    'Forex trading signals. 100% guaranteed profits. Join today',
    'Crypto mining investment: 10% daily returns. Limited slots',
    'Get rich quick scheme. Invest Ksh 1000 get Ksh 10000 in 24 hours',
    'Real estate investment opportunity. 50% returns guaranteed',
    
    # Job/Employment scams
    'Work from home job! Earn Ksh 5000 daily. Registration fee Ksh 1000',
    'Kazi ya online inakulipa Ksh 3000 kwa siku. Jisajili sasa',
    'Data entry job available. No experience needed. Pay Ksh 1500 to apply',
    'Recruitment: NGO jobs. Pay Ksh 3000 interview fee. Call 0711222333',
    
    # Delivery/Package scams
    'Your FedEx package held at customs. Pay Ksh 3000 to release',
    'DHL: Your parcel awaiting delivery. Clearance fee Ksh 2500 required',
    'Posta Kenya: Package arrived. Pay Ksh 1000 to collect',
    
    # Government/Authority impersonation
    'IMPORTANT: Your eCitizen account suspended. Verify identity',
    'KRA: Tax evasion case filed. Pay Ksh 50000 immediately',
    'Huduma Namba: Your registration incomplete. Send PIN to confirm',
    'NTSA: Your driving license suspended. Pay fine to 0712345678',
    'Immigration: Your passport application has issues. Call immediately',
    
    # Lottery/Prize scams
    'You won the FIFA World Cup lottery! Send Ksh 5000 processing fee',
    'Congratulations! Your Safaricom number won iPhone 15. Claim now',
    'UK National Lottery: Your email won GBP 500000. Contact agent',
    'Coca-Cola promotion: You won Ksh 1000000! Send details to claim',
    
    # Social media/WhatsApp scams
    'Hello dear, I am Mr. Johnson from UK. Need help to transfer funds',
    'Your WhatsApp will be deactivated. Verify at http://whatsapp-verify.tk',
    'Facebook security alert: Your account reported. Verify identity',
    'Instagram verification required. Your account will be deleted',
    
    # ========== SWAHILI SCAMS ==========
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
]

legit = [
    # ========== M-PESA TRANSACTIONS (LEGITIMATE) ==========
    'M-Pesa Ksh 500 to John successful. Balance: 2450',
    'M-Pesa: You received Ksh 1000 from Mary Wanjiku. Balance: Ksh 5000',
    'Safaricom: Ksh 200 airtime purchased. New balance: Ksh 800',
    'M-Pesa: You bought Ksh 100 airtime. Balance: Ksh 900',
    'Safaricom: Your M-Pesa statement for April is ready. Dial *334#',
    'M-Pesa: You have sent Ksh 500 to Peter. Transaction ID: MP123456',
    'Safaricom: Your M-Pesa balance is Ksh 3450 as at 10:30 AM',
    'M-Pesa: Ksh 2000 received from Employer Salary. New balance: Ksh 7000',
    
    # ========== BANK NOTIFICATIONS (LEGITIMATE) ==========
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
    
    # ========== UTILITY BILLS (LEGITIMATE) ==========
    'Your electricity token: 1234-5678-9012',
    'KPLC bill for May: Ksh 2350. Paybill 888880',
    'KPLC: Scheduled maintenance in your area on Sunday 2-5pm',
    'Nairobi Water: Your bill of Ksh 850 is due on 30th May',
    'KPLC: Your power will be disconnected if bill not paid by Friday',
    
    # ========== INSURANCE/GOVERNMENT (LEGITIMATE) ==========
    'NHIF payment for May received. Status: Active',
    'Your NHIF card is ready for collection at Huduma Centre',
    'NSSF: Your contribution for May of Ksh 2000 received',
    'Your KRA PIN certificate is ready. Download from iTax',
    'Your driving license renewal successful. Pick at Huduma Centre',
    'Huduma Namba update: Visit chief camp on Monday',
    'NSSF: Your statement for Q1 2024 is ready. Visit nssf.go.ke',
    'KRA: Your tax compliance certificate is ready for download',
    
    # ========== PERSONAL COMMUNICATION (LEGITIMATE) ==========
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
    
    # ========== SHOPPING/DELIVERY (LEGITIMATE) ==========
    'Jumia package delivered. Track: JM123456',
    'Your parcel from Jumia is out for delivery today',
    'Thank you for shopping at Naivas. Points earned: 50',
    'Carrefour: Your online order #ORD123 is ready for pickup',
    'Jumia: Your order #JM789 has been dispatched. Delivery by 5pm',
    'Kilimall: Your refund of Ksh 1500 has been processed',
    
    # ========== RELIGIOUS/SOCIAL (LEGITIMATE) ==========
    'Church service Sunday 9am. All welcome.',
    'Church harambee this Sunday. Contributions welcome',
    'Family dinner at Grandma place this Sunday. Bring dessert',
    'Prayer meeting this Wednesday at 6pm. All invited',
    'Wedding meeting this Saturday at 2pm. Please attend.',
    
    # ========== SCHOOL/EDUCATION (LEGITIMATE) ==========
    'School fees payment Ksh 15000 received. Receipt: SCH001',
    'Your child school report ready for collection on Friday',
    'Reminder: Parent-teacher meeting tomorrow at 2pm',
    'University admission letter ready. Collect from registry',
    'Exam results for Term 2 are out. Check the school portal.',
    
    # ========== TRAVEL/TRANSPORT (LEGITIMATE) ==========
    'Flight booking: KQ100 Nairobi-Mombasa confirmed',
    'Your Uber is arriving. Driver: John, Toyota Corolla KDA 123T',
    'SGR ticket: Nairobi-Mombasa on 15th June. Seat C12',
    'Kenya Airways: Your check-in for flight KQ101 is now open',
    'SGR: Your train to Mombasa departs at 3pm from Nairobi Terminus',
    
    # ========== HEALTH (LEGITIMATE) ==========
    'Reminder: Doctor appointment tomorrow 10am',
    'Your lab results are ready. Visit clinic to collect',
    'Dentist appointment confirmed for Friday at 3pm',
    'NHIF: Your biometric registration is complete. Card processing.',
    
    # ========== SERVICE NOTIFICATIONS (LEGITIMATE) ==========
    'Safaricom: Your data bundle expires tomorrow. Dial *544#',
    'Safaricom: Your Bonga Points balance is 500. Redeem now',
    'Airtel: Your daily data bonus of 50MB is ready',
    'Zuku: Your internet bill of Ksh 2500 is due',
    'DSTV: Your subscription expires in 7 days. Renew now',
    'Safaricom: You have successfully subscribed to Go Weekly at Ksh 99',
    'Safaricom: Your postpaid bill of Ksh 2500 is ready. Pay by 25th.',
    
    # ========== WORK/BUSINESS (LEGITIMATE) ==========
    'Your leave application has been approved. Enjoy your time off',
    'Staff meeting postponed to Tuesday. Check email for details',
    'Your invoice #INV001 has been paid. Amount: Ksh 45000',
    'The quarterly report is due by Friday. Please submit on time',
    'Client presentation confirmed for Thursday 10am. Prepare slides.',
]

# Clean all messages
scam = [clean_text(m) for m in scam]
legit = [clean_text(m) for m in legit]

print(f"Training Data: {len(scam)} scam + {len(legit)} legit = {len(scam)+len(legit)} total")

msgs = scam + legit
labels = [1]*len(scam) + [0]*len(legit)

# ============================================================
# MULTIPLE MODELS WITH CALIBRATION FOR PROBABILITIES
# ============================================================
models = {
    'LogisticRegression': Pipeline([
        ('vec', TfidfVectorizer(max_features=5000, ngram_range=(1,3), min_df=1, max_df=0.95)),
        ('clf', LogisticRegression(C=0.8, max_iter=3000, class_weight='balanced', random_state=42))
    ]),
    'CalibratedSVC': Pipeline([
        ('vec', TfidfVectorizer(max_features=5000, ngram_range=(1,2), min_df=1)),
        ('clf', CalibratedClassifierCV(LinearSVC(C=1.0, class_weight='balanced', random_state=42, max_iter=2000), cv=3))
    ]),
    'MultinomialNB': Pipeline([
        ('vec', TfidfVectorizer(max_features=5000, ngram_range=(1,2), min_df=1)),
        ('clf', MultinomialNB(alpha=0.05))
    ]),
    'SGDClassifier': Pipeline([
        ('vec', TfidfVectorizer(max_features=5000, ngram_range=(1,2), min_df=1)),
        ('clf', SGDClassifier(loss='modified_huber', penalty='l2', alpha=0.0001, max_iter=2000, class_weight='balanced', random_state=42))
    ]),
    'GradientBoosting': Pipeline([
        ('vec', TfidfVectorizer(max_features=3000, ngram_range=(1,2), min_df=1)),
        ('clf', GradientBoostingClassifier(n_estimators=150, max_depth=5, learning_rate=0.1, random_state=42))
    ]),
}

print('\n' + '='*60)
print('TRAINING MULTIPLE MODELS WITH 5-FOLD CROSS VALIDATION')
print('='*60)

best_model = None
best_score = 0
best_name = ''
results = []

for name, model in models.items():
    try:
        scores = cross_val_score(model, msgs, labels, cv=5, scoring='f1')
        avg = scores.mean()
        results.append((name, avg))
        print(f'\n{name}:')
        print(f'  CV Scores: {[round(s,3) for s in scores]}')
        print(f'  Average F1: {avg:.4f} ({avg*100:.1f}%)')
        
        if avg > best_score:
            best_score = avg
            best_name = name
            model.fit(msgs, labels)
            best_model = model
            print('  >>> NEW BEST MODEL!')
    except Exception as e:
        print(f'\n{name}: FAILED - {e}')

# ============================================================
# ENSEMBLE: Combine top 2 models if close scores
# ============================================================
print('\n' + '='*60)
print(f'BEST MODEL: {best_name}')
print(f'F1 Score: {best_score:.4f} ({best_score*100:.1f}%)')
print('='*60)

# Sort results
results.sort(key=lambda x: x[1], reverse=True)
print('\nFinal Rankings:')
for i, (name, score) in enumerate(results):
    medal = ['🥇','🥈','🥉'][i] if i < 3 else f'{i+1}.'
    print(f'  {medal} {name}: {score:.4f}')

# ============================================================
# SAVE BEST MODEL
# ============================================================
os.makedirs('detector/ml/models', exist_ok=True)
joblib.dump(best_model, 'detector/ml/models/scam_model.joblib')

metadata = {
    'model_name': best_name,
    'f1_score': float(best_score),
    'num_samples': len(msgs),
    'num_scam': len(scam),
    'num_legit': len(legit),
    'all_results': [(name, float(score)) for name, score in results]
}
with open('detector/ml/models/metadata.json', 'w') as f:
    json.dump(metadata, f, indent=2)
print(f'\nModel saved: {best_name} (F1: {best_score:.3f})')

# ============================================================
# COMPREHENSIVE TESTING WITH CONFIDENCE THRESHOLDS
# ============================================================
print('\n' + '='*60)
print('COMPREHENSIVE TESTING WITH CONFIDENCE LEVELS')
print('='*60)

# ============================================================
# CONFIDENCE THRESHOLDS FOR PRODUCTION
# ============================================================
HIGH_CONFIDENCE_THRESHOLD = 80  # Above this = definitely scam
SCAM_THRESHOLD = 60             # Above this = likely scam
LOW_CONFIDENCE_THRESHOLD = 40   # Below this = likely legitimate
SAFE_THRESHOLD = 20             # Below this = definitely safe

print("""
CONFIDENCE THRESHOLDS:
  >= {HIGH_CONFIDENCE_THRESHOLD}% : HIGH CONFIDENCE SCAM
  >= {SCAM_THRESHOLD}% : LIKELY SCAM
  {LOW_CONFIDENCE_THRESHOLD}-{SCAM_THRESHOLD}% : UNCERTAIN (needs keyword check)
  <= {LOW_CONFIDENCE_THRESHOLD}% : LIKELY LEGITIMATE
  <= {SAFE_THRESHOLD}% : HIGH CONFIDENCE SAFE
""")

tests = [
    # Clear SCAMS (should score >80%)
    ('URGENT: Your M-Pesa suspended. Send PIN NOW to reactivate!', 'SCAM', 'HIGH'),
    ('Congrats! You won Ksh 1,000,000! Send 1000 to claim your prize.', 'SCAM', 'HIGH'),
    ('Akaunti yako imefungwa. Tuma PIN yako sasa hivi!', 'SCAM', 'HIGH'),
    ('Send Ksh 500 to 0711222333 to receive your M-Shwari loan', 'SCAM', 'HIGH'),
    ('Security Alert: Verify your account immediately or face closure', 'SCAM', 'HIGH'),
    ('Double your bitcoin in 24 hours! Guaranteed profit!', 'SCAM', 'HIGH'),
    ('Breaking: Your bank account hacked. Call 0711987654 now!', 'SCAM', 'HIGH'),
    ('Tuma Pesa kwa 0700111222 upokee tuzo yako ya Ksh 500,000', 'SCAM', 'HIGH'),
    
    # Tricky cases - sound like scam but are LEGIT
    ('KCB: We detected unusual activity. Please call our fraud hotline at 0711123456.', 'LEGIT', 'MED'),
    ('Equity Bank: Did you attempt to log in from a new device? Reply YES or NO.', 'LEGIT', 'MED'),
    ('Safaricom: You have won 500 Bonga Points in our weekly draw! Points credited.', 'LEGIT', 'MED'),
    ('Safaricom: Your data bundle expires tomorrow. Dial *544# to renew.', 'LEGIT', 'HIGH'),
    ('KCB: Your account statement shows unusual activity. Visit any branch.', 'LEGIT', 'MED'),
    ('M-Pesa: Ksh 500 to John successful. Balance: 2450', 'LEGIT', 'HIGH'),
    ('Your electricity token: 5678-1234-9012. Units: 20kWh', 'LEGIT', 'HIGH'),
    
    # Clear LEGIT (should score <20%)
    ('Hi mom, can you pick up bread on your way home?', 'LEGIT', 'HIGH'),
    ('Church service this Sunday at 9am. All are welcome.', 'LEGIT', 'HIGH'),
    ('Doctor appointment reminder: Tomorrow at 10:30am', 'LEGIT', 'HIGH'),
    ('Meeting postponed to 4pm. Please confirm your availability.', 'LEGIT', 'HIGH'),
    ('Your KCB salary of Ksh 50000 has been credited.', 'LEGIT', 'HIGH'),
    ('Safaricom: Your data bundle of 1GB expires today. Dial *544#', 'LEGIT', 'HIGH'),
    ('Your NHIF payment of Ksh 500 for May has been received', 'LEGIT', 'HIGH'),
    
    # UNCERTAIN cases (borderline)
    ('Your account security needs updating. Visit safaricom.com/security to update.', 'LEGIT', 'LOW'),
    ('Congratulations! You have been selected for our customer loyalty program.', 'LEGIT', 'LOW'),
    ('Reminder: Your subscription will auto-renew tomorrow. Text STOP to cancel.', 'LEGIT', 'LOW'),
]

correct = 0
high_confidence_correct = 0
total_high_confidence = 0
uncertain_count = 0

for msg, expected, confidence_level in tests:
    try:
        proba = best_model.predict_proba([clean_text(msg)])[0][1] * 100
    except:
        decision = best_model.decision_function([clean_text(msg)])[0]
        proba = 1 / (1 + pow(2.71828, -decision)) * 100
    
    # Determine prediction with confidence thresholds
    if proba >= HIGH_CONFIDENCE_THRESHOLD:
        predicted = 'SCAM'
        ml_confidence = 'HIGH'
    elif proba >= SCAM_THRESHOLD:
        predicted = 'SCAM'
        ml_confidence = 'MED'
    elif proba >= LOW_CONFIDENCE_THRESHOLD:
        predicted = 'LEGIT'
        ml_confidence = 'LOW'  # Uncertain zone
        uncertain_count += 1
    elif proba >= SAFE_THRESHOLD:
        predicted = 'LEGIT'
        ml_confidence = 'MED'
    else:
        predicted = 'LEGIT'
        ml_confidence = 'HIGH'
    
    # Check whitelist for known legitimate patterns
    if is_known_legitimate(msg) and proba < HIGH_CONFIDENCE_THRESHOLD:
        predicted = 'LEGIT'
        ml_confidence = 'HIGH'
    
    ok = predicted == expected
    if ok: correct += 1
    if ml_confidence == 'HIGH':
        total_high_confidence += 1
        if ok: high_confidence_correct += 1
    
    icon = '✓' if ok else '✗'
    print(f'  [{icon}] {proba:5.1f}% ({ml_confidence:4s}) | Pred: {predicted:5s} | True: {expected:5s} | {msg[:60]}')

# ============================================================
# FINAL REPORT
# ============================================================
print(f'\n{"="*60}')
print('FINAL REPORT')
print(f'{"="*60}')
print(f'Model:              {best_name}')
print(f'CV F1 Score:        {best_score:.4f} ({best_score*100:.1f}%)')
print(f'Test Accuracy:      {correct}/{len(tests)} ({correct/len(tests)*100:.0f}%)')
print(f'High Conf Accuracy: {high_confidence_correct}/{total_high_confidence} ({high_confidence_correct/max(1,total_high_confidence)*100:.0f}%)')
print(f'Uncertain Cases:    {uncertain_count}/{len(tests)} ({uncertain_count/len(tests)*100:.0f}%)')
print(f'Training Data:      {len(msgs)} messages ({len(scam)} scam, {len(legit)} legit)')
print('\nConfidence Thresholds:')
print(f'  HIGH SCAM:  >= {HIGH_CONFIDENCE_THRESHOLD}%')
print(f'  LIKELY SCAM: >= {SCAM_THRESHOLD}%')
print(f'  UNCERTAIN:   {LOW_CONFIDENCE_THRESHOLD}-{SCAM_THRESHOLD}%')
print(f'  LIKELY SAFE: <= {LOW_CONFIDENCE_THRESHOLD}%')
print(f'  HIGH SAFE:   <= {SAFE_THRESHOLD}%')
print('\nModel saved to: detector/ml/models/scam_model.joblib')
print(f'{"="*60}')