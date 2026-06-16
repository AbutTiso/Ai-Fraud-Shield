# detector/ml_trainer.py
"""
Context-Aware ML Model Training Pipeline for Fraud Detection
Trains models using database reports + hardcoded examples + context markers
Understands that legitimate sites can use words that appear in scams
"""

import os
import sys
import pickle
import json
import re
import numpy as np
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.naive_bayes import MultinomialNB, ComplementNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
import joblib

# Django setup
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fraudshield.settings')
django.setup()

from detector.models import ScamReport


# ============================================================
# CONTEXT-AWARE WHITELIST — Legitimate domains & patterns
# ============================================================
SAFE_DOMAINS = {
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'whatsapp.com', 'telegram.org', 'youtube.com', 'wikipedia.org',
    'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
    'github.com', 'gitlab.com', 'stackoverflow.com', 'linkedin.com',
    'safaricom.co.ke', 'airtel.co.ke', 'telkom.co.ke',
    'kcbgroup.com', 'equitybank.co.ke', 'coopbank.co.ke', 'absabank.co.ke',
    'kra.go.ke', 'ecitizen.go.ke', 'nssf.go.ke', 'nhif.go.ke',
    'jumia.co.ke', 'kilimall.co.ke',
}

SAFE_CONTEXTS = {
    'bank_notification': [
        r'(?:kcb|equity|coop|absa|stanbic|ncba|family)\s*:',
        r'salary\s+(?:of\s+)?(?:ksh|kes)\s*\d+\s+credited',
        r'loan\s+payment\s+(?:of\s+)?(?:ksh|kes)\s*\d+\s+received',
        r'standing\s+order\s+(?:of\s+)?(?:ksh|kes)\s*\d+\s+processed',
        r'cheque\s+(?:book|deposited|cleared)',
        r'fixed\s+deposit\s+(?:matured|renewed)',
    ],
    'mpesa_transaction': [
        r'm-pesa\s*:\s*ksh\s*\d[\d,]*\s+(?:to|from)\s+\w+\s+(?:successful|completed)',
        r'm-pesa\s*:\s*you\s+(?:received|sent)\s+ksh\s*\d+',
        r'm-pesa\s*:\s*(?:your\s+)?balance\s+(?:is|:)',
        r'm-pesa\s*:\s*transaction\s+(?:id|cost)\s+[a-z0-9]+',
    ],
    'service_notification': [
        r'(?:your\s+)?(?:data\s+bundle|airtime|subscription)\s+(?:expir|renew)',
        r'(?:your\s+)?(?:bill|statement|invoice)\s+(?:is\s+ready|available|due)',
        r'(?:appointment|booking|reservation)\s+(?:confirmed|reminder)',
        r'(?:flight|train|bus)\s+(?:booking|ticket|departure)',
    ],
    'personal_message': [
        r'^(?:hi|hello|hey|habari|niaje|vipi)\b',
        r'\b(?:please|pls|kindly)\b.*\b(?:send|share|tell|bring|pick|buy)\b',
        r'\b(?:meeting|dinner|lunch|party|wedding|church|prayer)\b',
        r'\b(?:happy\s+birthday|congratulations|pole|get\s+well)\b',
    ],
}

# Words that are suspicious ONLY outside safe contexts
CONTEXT_DEPENDENT_WORDS = {
    'verify': {
        'safe_in': ['bank_notification', 'mpesa_transaction', 'service_notification'],
        'dangerous_in': ['unsolicited_sms', 'unknown_sender', 'with_urgency'],
    },
    'update': {
        'safe_in': ['bank_notification', 'service_notification'],
        'dangerous_in': ['unsolicited_sms', 'with_link', 'with_urgency'],
    },
    'confirm': {
        'safe_in': ['bank_notification', 'mpesa_transaction', 'service_notification'],
        'dangerous_in': ['unsolicited_sms', 'with_pin_request'],
    },
    'account': {
        'safe_in': ['bank_notification', 'mpesa_transaction', 'service_notification'],
        'dangerous_in': ['unsolicited_sms', 'with_urgency', 'with_threat'],
    },
    'login': {
        'safe_in': ['service_notification'],
        'dangerous_in': ['unsolicited_sms', 'with_link'],
    },
    'security': {
        'safe_in': ['bank_notification', 'service_notification'],
        'dangerous_in': ['unsolicited_sms', 'with_urgency', 'with_pin_request'],
    },
    'suspended': {
        'safe_in': [],  # Almost always suspicious
        'dangerous_in': ['any_context'],
    },
    'blocked': {
        'safe_in': ['service_notification'],  # "Your card blocked? Call us"
        'dangerous_in': ['unsolicited_sms', 'with_urgency'],
    },
    'urgent': {
        'safe_in': [],  # Legitimate orgs rarely use "urgent"
        'dangerous_in': ['any_context'],
    },
    'winner': {
        'safe_in': ['known_promotion'],
        'dangerous_in': ['unsolicited_sms', 'with_fee_request'],
    },
    'prize': {
        'safe_in': ['known_promotion'],
        'dangerous_in': ['unsolicited_sms', 'with_fee_request'],
    },
    'loan': {
        'safe_in': ['bank_notification', 'mpesa_transaction'],
        'dangerous_in': ['unsolicited_sms', 'with_fee_request'],
    },
    'pin': {
        'safe_in': [],  # Legitimate orgs NEVER ask for PIN via SMS
        'dangerous_in': ['any_context'],
    },
    'otp': {
        'safe_in': ['bank_notification'],  # Some banks send OTP for transactions
        'dangerous_in': ['unsolicited_sms', 'with_urgency'],
    },
    'password': {
        'safe_in': [],  # Legitimate orgs NEVER ask for password via SMS
        'dangerous_in': ['any_context'],
    },
}


class ContextAwareFraudTrainer:
    """
    Context-aware ML trainer that understands legitimate vs scam contexts.
    Words like "verify" are safe in bank notifications but dangerous in unsolicited SMS.
    """
    
    def __init__(self):
        self.models = {}
        self.model_metrics = {}
        self.training_date = datetime.now()
        self.training_data_size = 0
    
    def _add_context_markers(self, text):
        """
        Add context markers to help model understand word usage.
        Marks what context the message appears in.
        """
        text_lower = text.lower()
        markers = []
        safe_contexts_found = []
        dangerous_signals = []
        
        # Detect safe contexts
        for context_name, patterns in SAFE_CONTEXTS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    safe_contexts_found.append(context_name)
                    break
        
        # Detect dangerous signals
        if re.search(r'(?:send|share|provide|enter|type)\s+(?:your\s+)?(?:pin|otp|mpin|password)', text_lower):
            dangerous_signals.append('with_pin_request')
        if re.search(r'http[s]?://|www\.|bit\.ly|tinyurl|short\.link', text_lower):
            dangerous_signals.append('with_link')
        if re.search(r'urgent|immediately|asap|haraka|sasa\s+hivi', text_lower):
            dangerous_signals.append('with_urgency')
        if re.search(r'pay\s+(?:ksh|kes)\s*\d+|send\s+(?:ksh|kes)\s*\d+|processing\s+fee', text_lower):
            dangerous_signals.append('with_fee_request')
        if re.search(r'suspended|blocked|locked|deactivated|closed|terminated', text_lower):
            dangerous_signals.append('with_threat')
        if re.search(r'\b(07|01|2547)\d{8}\b', text_lower):
            dangerous_signals.append('unknown_sender')
        if re.search(r'won|winner|congratulations|prize|lotto|jackpot|giveaway', text_lower):
            dangerous_signals.append('unsolicited_prize')
        
        # Determine overall context
        if safe_contexts_found and not dangerous_signals:
            markers.append(f'SAFE_CONTEXT:{"|".join(safe_contexts_found)}')
        elif dangerous_signals:
            markers.append(f'DANGER_SIGNALS:{"|".join(dangerous_signals)}')
        
        # Check for context-dependent words
        for word, contexts in CONTEXT_DEPENDENT_WORDS.items():
            if word in text_lower:
                if safe_contexts_found and any(s in contexts['safe_in'] for s in safe_contexts_found):
                    markers.append(f'SAFE_WORD:{word}')
                else:
                    markers.append(f'DANGER_WORD:{word}')
        
        if markers:
            return f"[{'|'.join(markers)}] {text}"
        return f"[UNKNOWN_CONTEXT] {text}"
    
    def _is_known_safe(self, text):
        """Check if message is from a known safe context"""
        text_lower = text.lower()
        
        # Check safe contexts without dangerous signals
        for context_name, patterns in SAFE_CONTEXTS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    # Verify no dangerous signals
                    has_pin_request = re.search(r'(?:send|share|provide)\s+(?:your\s+)?(?:pin|otp|mpin|password)', text_lower)
                    has_urgency = re.search(r'urgent|immediately|asap|haraka', text_lower)
                    has_unknown_link = re.search(r'bit\.ly|tinyurl|short\.link|http://(?!.*safaricom|.*kcb|.*equity)', text_lower)
                    
                    if not has_pin_request and not has_urgency and not has_unknown_link:
                        return True, context_name
        
        return False, None
    
    def load_training_data(self, min_samples=100):
        """Load training data from database with context awareness"""
        reports = ScamReport.objects.all()
        
        if reports.count() < min_samples:
            print(f"⚠️ Only {reports.count()} samples. Need at least {min_samples}.")
            return None, None
        
        texts = []
        labels = []
        skipped_safe = 0
        
        for report in reports:
            if report.content and len(report.content) > 10:
                # Check if this is from a known safe context
                is_safe, safe_context = self._is_known_safe(report.content)
                
                if is_safe and report.risk_score >= 40:
                    # High score but known safe context — likely mislabeled
                    # Use lower label to teach model context
                    labels.append(0)  # Mark as legitimate despite high score
                    skipped_safe += 1
                else:
                    label = 1 if report.risk_score >= 40 else 0
                    labels.append(label)
                
                # Add context markers
                marked_text = self._add_context_markers(report.content[:2000])
                texts.append(marked_text)
        
        self.training_data_size = len(texts)
        
        print(f"✅ Loaded {len(texts)} samples from database")
        print(f"   Scam samples: {sum(labels)}")
        print(f"   Legitimate samples: {len(labels) - sum(labels)}")
        if skipped_safe:
            print(f"   🔄 Reclassified {skipped_safe} high-score reports as legitimate (safe context)")
        
        return texts, labels
    
    def load_training_data_with_hardcoded(self, min_samples=100):
        """Load training data from database + hardcoded examples"""
        # Load database data
        db_texts, db_labels = self.load_training_data(min_samples=0)
        
        # Load hardcoded data
        hc_texts, hc_labels = self._get_hardcoded_data()
        
        # Load feedback corrections
        fb_texts, fb_labels = self._load_feedback_data()
        
        # Combine
        all_texts = (db_texts or []) + hc_texts + fb_texts
        all_labels = (db_labels or []) + hc_labels + fb_labels
        
        if len(all_texts) < min_samples:
            print(f"⚠️ Only {len(all_texts)} total samples. Need at least {min_samples}.")
            return None, None
        
        # Add context markers to all
        all_texts = [self._add_context_markers(t) for t in all_texts]
        
        self.training_data_size = len(all_texts)
        print(f"\n📊 Total Training Data: {len(all_texts)} examples")
        print(f"   Scam: {sum(all_labels)} ({sum(all_labels)/len(all_labels)*100:.1f}%)")
        print(f"   Legitimate: {len(all_labels)-sum(all_labels)} ({(len(all_labels)-sum(all_labels))/len(all_labels)*100:.1f}%)")
        
        return all_texts, all_labels
    
    def _get_hardcoded_data(self):
        """Get hardcoded training examples"""
        # Import from the new prepare_data module
        try:
            from detector.ml.training.prepare_data import get_hardcoded_training_data
            return get_hardcoded_training_data()
        except ImportError:
            pass
        
        # Fallback: basic examples
        scam = [
            'URGENT: Your M-Pesa suspended. Send PIN to verify.',
            'Congratulations! You won Ksh 250000. Click http://scam.com',
            'Send MPIN to 0700000000 for M-Shwari bonus',
            'Tuma pesa kwa 0711222333 upokee zawadi',
            'Your bank account blocked. Call 0712345678 immediately',
            'Winner! Claim iPhone by sending OTP to 0711222333',
            'You have been selected for a Ksh 500000 prize. Pay Ksh 1000 to claim.',
            'Breaking: Police case filed against you. Call 0711222333 urgently',
        ]
        legit = [
            'M-Pesa Ksh 500 to John successful. Balance: 2450',
            'KCB: Salary 45000 credited to your account.',
            'Hello, pick up milk on your way home please',
            'Meeting at 3pm. Bring laptop and charger.',
            'Church service Sunday 9am. All welcome.',
            'Your KCB loan payment of Ksh 5000 received. Thank you',
            'Safaricom: Your data bundle expires tomorrow. Dial *544#',
            'Your electricity token: 1234-5678-9012',
        ]
        return [self._add_context_markers(m) for m in scam + legit], [1]*len(scam) + [0]*len(legit)
    
    def _load_feedback_data(self):
        """Load user feedback corrections"""
        feedback_path = os.path.join(os.path.dirname(__file__), 'data', 'feedback_data.json')
        texts, labels = [], []
        
        if os.path.exists(feedback_path):
            try:
                with open(feedback_path) as f:
                    feedbacks = json.load(f)
                for fb in feedbacks:
                    if fb.get('original_text') and fb.get('user_verdict'):
                        texts.append(fb['original_text'])
                        labels.append(1 if fb['user_verdict'] == 'scam' else 0)
                if texts:
                    print(f"   📝 Loaded {len(texts)} feedback corrections")
            except:
                pass
        return texts, labels
    
    def train_sms_model(self, texts, labels):
        """Train context-aware SMS scam detection model"""
        print("\n" + "="*60)
        print("📱 Training Context-Aware SMS Detection Model")
        print("="*60)
        
        # Try multiple models
        models = {
            'LogisticRegression': Pipeline([
                ('tfidf', TfidfVectorizer(max_features=8000, ngram_range=(1, 4), min_df=1, max_df=0.95, sublinear_tf=True)),
                ('clf', LogisticRegression(C=0.8, max_iter=3000, class_weight='balanced', random_state=42))
            ]),
            'CalibratedSVC': Pipeline([
                ('tfidf', TfidfVectorizer(max_features=6000, ngram_range=(1, 3), min_df=1, sublinear_tf=True)),
                ('clf', CalibratedClassifierCV(LinearSVC(C=1.0, class_weight='balanced', random_state=42, max_iter=2000), cv=3))
            ]),
            'ComplementNB': Pipeline([
                ('tfidf', TfidfVectorizer(max_features=6000, ngram_range=(1, 3), min_df=1, sublinear_tf=True)),
                ('clf', ComplementNB(alpha=0.1, norm=False))
            ]),
        }
        
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.15, random_state=42, stratify=labels
        )
        
        best_model = None
        best_score = 0
        best_name = ''
        
        for name, model in models.items():
            print(f"\n🔧 Training {name}...")
            try:
                cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
                cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='f1')
                avg_score = cv_scores.mean()
                
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                test_f1 = f1_score(y_test, y_pred)
                
                print(f"   CV F1: {avg_score:.4f} | Test F1: {test_f1:.4f}")
                
                if avg_score > best_score:
                    best_score = avg_score
                    best_name = name
                    # Train on full data
                    model.fit(texts, labels)
                    best_model = model
                    print("   ✅ New best model!")
            except Exception as e:
                print(f"   ❌ Failed: {e}")
        
        self.models['sms'] = best_model
        self.model_metrics['sms'] = {
            'model_name': best_name,
            'cv_f1': float(best_score),
            'training_samples': len(texts),
        }
        
        print(f"\n🏆 Best SMS Model: {best_name} (F1: {best_score:.4f})")
        return best_model
    
    def save_models(self, models_dir='ml_models'):
        """Save models to disk"""
        os.makedirs(models_dir, exist_ok=True)
        
        for name, model in self.models.items():
            path = os.path.join(models_dir, f'{name}_model.joblib')
            joblib.dump(model, path)
            print(f"   💾 Saved {name} to {path}")
        
        # Also save for detector/ml/models
        ml_models_dir = os.path.join(os.path.dirname(__file__), 'ml', 'models')
        os.makedirs(ml_models_dir, exist_ok=True)
        if 'sms' in self.models:
            joblib.dump(self.models['sms'], os.path.join(ml_models_dir, 'scam_model.joblib'))
        
        metadata = {
            'model_metrics': {k: {kk: float(vv) if isinstance(vv, (float, np.floating)) else vv for kk, vv in v.items()} for k, v in self.model_metrics.items()},
            'training_date': self.training_date.isoformat(),
            'training_samples': self.training_data_size,
        }
        with open(os.path.join(ml_models_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
        
        print(f"\n✅ Models saved to '{models_dir}/' and 'detector/ml/models/'")
    
    def load_models(self, models_dir='ml_models'):
        """Load trained models"""
        for name in ['sms', 'url', 'ensemble']:
            path = os.path.join(models_dir, f'{name}_model.joblib')
            if os.path.exists(path):
                self.models[name] = joblib.load(path)
                print(f"✅ Loaded {name} model")
        
        return len(self.models) > 0
    
    def predict_sms(self, text):
        """Predict with context awareness"""
        if 'sms' not in self.models:
            return None
        
        # First check if this is from a known safe context
        is_safe, safe_context = self._is_known_safe(text)
        if is_safe:
            return {
                'is_scam': False,
                'confidence': 0.99,
                'scam_probability': 5.0,
                'prediction': 'LEGITIMATE',
                'context': safe_context,
                'context_override': True,
            }
        
        # Use ML model
        marked_text = self._add_context_markers(text)
        model = self.models['sms']
        
        try:
            proba = model.predict_proba([marked_text])[0]
            scam_prob = proba[1] if len(proba) > 1 else proba[0]
        except:
            pred = model.predict([marked_text])[0]
            scam_prob = float(pred)
        
        is_scam = scam_prob >= 0.5
        
        return {
            'is_scam': is_scam,
            'confidence': float(scam_prob if is_scam else 1 - scam_prob),
            'scam_probability': float(scam_prob * 100),
            'prediction': 'SCAM' if is_scam else 'LEGITIMATE',
            'context_override': False,
        }


def run_training():
    """Main training function"""
    print("\n" + "="*70)
    print("🚀 CONTEXT-AWARE ML MODEL TRAINING")
    print("="*70)
    
    trainer = ContextAwareFraudTrainer()
    texts, labels = trainer.load_training_data_with_hardcoded()
    
    if texts is None:
        print("\n❌ Not enough data. Need at least 100 samples.")
        return None
    
    trainer.train_sms_model(texts, labels)
    trainer.save_models()
    
    print("\n✅ Training complete!")
    return trainer


if __name__ == "__main__":
    run_training()