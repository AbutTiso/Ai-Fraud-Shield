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

def clean_text(text):
    """Clean text for better ML performance"""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', ' URL ', text)
    text = re.sub(r'\b(07|01|2547)\d{8}\b', ' PHONE ', text)
    text = re.sub(r'ksh\s*\d[\d,]*', ' MONEY ', text)
    text = re.sub(r'[^a-zA-Z0-9\s!?]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# ============================================================
# EXTENDED TRAINING DATA - 100+ Examples
# ============================================================
scam = [
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
    
    # Swahili scams
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
]

legit = [
    # M-Pesa transaction notifications
    'M-Pesa Ksh 500 to John successful. Balance: 2450',
    'M-Pesa: You received Ksh 1000 from Mary Wanjiku. Balance: Ksh 5000',
    'Safaricom: Ksh 200 airtime purchased. New balance: Ksh 800',
    'M-Pesa: You bought Ksh 100 airtime. Balance: Ksh 900',
    'Safaricom: Your M-Pesa statement for April is ready. Dial *334#',
    
    # Banking notifications
    'KCB: Salary 45000 credited to your account.',
    'Your KCB loan payment of Ksh 5000 received. Thank you',
    'Equity Bank: Your statement for April is ready',
    'Co-op Bank: Loan payment of Ksh 15000 due on 25th. Ref: LOAN001',
    'Absa: Your credit card payment of Ksh 25000 received',
    'Standard Chartered: New credit card delivered to your branch',
    'NCBA: Fixed deposit matured. Interest earned: Ksh 5000',
    
    # Utility bills
    'Your electricity token: 1234-5678-9012',
    'KPLC bill for May: Ksh 2350. Paybill 888880',
    'KPLC: Scheduled maintenance in your area on Sunday 2-5pm',
    'Nairobi Water: Your bill of Ksh 850 is due on 30th May',
    
    # Insurance/Government
    'NHIF payment for May received. Status: Active',
    'Your NHIF card is ready for collection at Huduma Centre',
    'NSSF: Your contribution for May of Ksh 2000 received',
    'Your KRA PIN certificate is ready. Download from iTax',
    'Your driving license renewal successful. Pick at Huduma Centre',
    'Huduma Namba update: Visit chief camp on Monday',
    
    # Personal communication
    'Hello, pick up milk on your way home please',
    'Meeting at 3pm. Bring laptop and charger.',
    'Happy birthday! Have a wonderful day ahead.',
    'Dinner tonight at 7pm? Usual place.',
    'Please confirm your attendance for the wedding on Saturday',
    'Karibu nyumbani. Dinner iko tayari',
    'Can you send me the presentation before the meeting?',
    'Reminder: Pick up kids from school at 4pm',
    
    # Shopping/Delivery
    'Jumia package delivered. Track: JM123456',
    'Your parcel from Jumia is out for delivery today',
    'Thank you for shopping at Naivas. Points earned: 50',
    'Carrefour: Your online order #ORD123 is ready for pickup',
    
    # Religious/Social
    'Church service Sunday 9am. All welcome.',
    'Church harambee this Sunday. Contributions welcome',
    'Family dinner at Grandma place this Sunday. Bring dessert',
    'Prayer meeting this Wednesday at 6pm. All invited',
    
    # School/Education
    'School fees payment Ksh 15000 received. Receipt: SCH001',
    'Your child school report ready for collection on Friday',
    'Reminder: Parent-teacher meeting tomorrow at 2pm',
    'University admission letter ready. Collect from registry',
    
    # Travel/Transport
    'Flight booking: KQ100 Nairobi-Mombasa confirmed',
    'Your Uber is arriving. Driver: John, Toyota Corolla KDA 123T',
    'SGR ticket: Nairobi-Mombasa on 15th June. Seat C12',
    
    # Health
    'Reminder: Doctor appointment tomorrow 10am',
    'Your lab results are ready. Visit clinic to collect',
    'Dentist appointment confirmed for Friday at 3pm',
    
    # Service notifications
    'Safaricom: Your data bundle expires tomorrow. Dial *544#',
    'Safaricom: Your Bonga Points balance is 500. Redeem now',
    'Airtel: Your daily data bonus of 50MB is ready',
    'Zuku: Your internet bill of Ksh 2500 is due',
    'DSTV: Your subscription expires in 7 days. Renew now',
    
    # Work/Business
    'Your leave application has been approved. Enjoy your time off',
    'Staff meeting postponed to Tuesday. Check email for details',
    'Your invoice #INV001 has been paid. Amount: Ksh 45000',
    'The quarterly report is due by Friday. Please submit on time',
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
# COMPREHENSIVE TESTING
# ============================================================
print('\n' + '='*60)
print('COMPREHENSIVE TESTING (16 Tests)')
print('='*60)

tests = [
    # Clear SCAMS
    ('URGENT: Your M-Pesa suspended. Send PIN NOW to reactivate!', 'SCAM'),
    ('Congrats! You won Ksh 1,000,000! Send 1000 to claim your prize.', 'SCAM'),
    ('Akaunti yako imefungwa. Tuma PIN yako sasa hivi!', 'SCAM'),
    ('Send Ksh 500 to 0711222333 to receive your M-Shwari loan', 'SCAM'),
    ('Security Alert: Verify your account immediately or face closure', 'SCAM'),
    ('Double your bitcoin in 24 hours! Guaranteed profit!', 'SCAM'),
    ('Breaking: Your bank account hacked. Call 0711987654 now!', 'SCAM'),
    ('Tuma Pesa kwa 0700111222 upokee tuzo yako ya Ksh 500,000', 'SCAM'),
    
    # Clear LEGIT
    ('Hi mom, can you pick up bread on your way home?', 'LEGIT'),
    ('Your KCB salary of Ksh 50000 has been credited.', 'LEGIT'),
    ('Church service this Sunday at 9am. All are welcome.', 'LEGIT'),
    ('Your electricity token: 5678-1234-9012. Units: 20kWh', 'LEGIT'),
    ('Doctor appointment reminder: Tomorrow at 10:30am', 'LEGIT'),
    ('Your NHIF payment of Ksh 500 for May has been received', 'LEGIT'),
    ('Meeting postponed to 4pm. Please confirm your availability.', 'LEGIT'),
    ('Safaricom: Your data bundle of 1GB expires today. Dial *544#', 'LEGIT'),
]

correct = 0
high_confidence = 0
for msg, expected in tests:
    try:
        proba = best_model.predict_proba([clean_text(msg)])[0][1] * 100
    except:
        decision = best_model.decision_function([clean_text(msg)])[0]
        proba = 1 / (1 + pow(2.71828, -decision)) * 100
    
    predicted = 'SCAM' if proba >= 50 else 'LEGIT'
    ok = predicted == expected
    if ok: correct += 1
    if (proba >= 80 or proba <= 20): high_confidence += 1
    
    icon = '✓' if ok else '✗'
    conf = 'HIGH' if (proba >= 80 or proba <= 20) else 'MED' if (proba >= 65 or proba <= 35) else 'LOW'
    print(f'  [{icon}] {proba:5.1f}% ({conf:4s}) | Pred: {predicted:5s} | True: {expected:5s} | {msg[:55]}')

# ============================================================
# FINAL REPORT
# ============================================================
print(f'\n{"="*60}')
print('FINAL REPORT')
print(f'{"="*60}')
print(f'Model:          {best_name}')
print(f'CV F1 Score:    {best_score:.4f} ({best_score*100:.1f}%)')
print(f'Test Accuracy:  {correct}/{len(tests)} ({correct/len(tests)*100:.0f}%)')
print(f'High Conf:      {high_confidence}/{len(tests)} ({high_confidence/len(tests)*100:.0f}%)')
print(f'Training Data:  {len(msgs)} messages ({len(scam)} scam, {len(legit)} legit)')
print('\nModel saved to: detector/ml/models/scam_model.joblib')
print(f'{"="*60}')