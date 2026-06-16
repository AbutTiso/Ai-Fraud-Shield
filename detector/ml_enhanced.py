# detector/ml_enhanced.py
"""
Context-Aware ML Enhancement for Rule-Based Detectors
Hybrid approach: Rules + Context Analysis + ML for maximum accuracy
Understands that legitimate sites can use scam-associated words
"""

import re
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import cross_val_score
import joblib
from pathlib import Path
import json
from datetime import datetime


# ============================================================
# CONTEXT-AWARE WORD ANALYSIS
# ============================================================

# Words that appear in BOTH scams and legitimate messages
# Context determines if they're dangerous
CONTEXT_DEPENDENT_WORDS = {
    'verify': {
        'safe_contexts': ['bank_notification', 'service_notification', 'known_sender'],
        'dangerous_contexts': ['unsolicited', 'with_urgency', 'with_pin_request'],
        'safe_examples': ['Verify your account at kcbgroup.com', 'Please verify your identity at the branch'],
        'scam_examples': ['Verify your account NOW or lose access!', 'Send PIN to verify'],
    },
    'update': {
        'safe_contexts': ['bank_notification', 'service_notification', 'app_store'],
        'dangerous_contexts': ['unsolicited', 'with_link', 'with_urgency'],
        'safe_examples': ['Your app update is available', 'Update your contact details at our branch'],
        'scam_examples': ['URGENT: Update your payment details now!', 'Click to update account'],
    },
    'confirm': {
        'safe_contexts': ['bank_notification', 'mpesa_transaction', 'appointment'],
        'dangerous_contexts': ['unsolicited', 'with_pin_request'],
        'safe_examples': ['Confirm your appointment for tomorrow', 'Transaction confirmed: Ksh 500'],
        'scam_examples': ['Confirm your PIN to receive money', 'Confirm identity with OTP'],
    },
    'account': {
        'safe_contexts': ['bank_notification', 'service_notification'],
        'dangerous_contexts': ['unsolicited', 'with_urgency', 'with_threat'],
        'safe_examples': ['Your account statement is ready', 'Account balance: Ksh 5000'],
        'scam_examples': ['Your account will be BLOCKED!', 'Account suspended. Verify now!'],
    },
    'security': {
        'safe_contexts': ['bank_notification', 'official_communication'],
        'dangerous_contexts': ['unsolicited', 'with_urgency', 'with_link'],
        'safe_examples': ['Security update available for your app', 'Visit our security center at google.com'],
        'scam_examples': ['Security alert! Your account hacked!', 'Security breach: Send OTP now'],
    },
    'login': {
        'safe_contexts': ['service_notification', 'app_notification'],
        'dangerous_contexts': ['unsolicited', 'with_link'],
        'safe_examples': ['New login from Chrome on Windows', 'Login to your account at netflix.com'],
        'scam_examples': ['Suspicious login detected! Click to secure', 'Login verify: http://fake.com'],
    },
    'password': {
        'safe_contexts': ['service_notification', 'app_notification'],
        'dangerous_contexts': ['unsolicited', 'any_sms'],  # Legitimate orgs don't ask for passwords via SMS
        'safe_examples': ['Password changed successfully', 'Reset your password at google.com'],
        'scam_examples': ['Send your password to verify', 'Password expired: Send new one'],
    },
    'limited': {
        'safe_contexts': ['marketing', 'known_promotion', 'sale'],
        'dangerous_contexts': ['unsolicited', 'with_urgency', 'with_fee'],
        'safe_examples': ['Limited time offer at Carrefour', 'Limited stock available online'],
        'scam_examples': ['LIMITED TIME: Send money now!', 'Limited slots: Pay to join'],
    },
    'free': {
        'safe_contexts': ['marketing', 'known_promotion', 'service_notification'],
        'dangerous_contexts': ['unsolicited', 'with_link', 'with_fee'],
        'safe_examples': ['Free delivery on orders above Ksh 2000', 'Your free trial starts today'],
        'scam_examples': ['FREE iPhone! Click to claim!', 'Free money: Send Ksh 500 to receive'],
    },
    'offer': {
        'safe_contexts': ['marketing', 'bank_notification', 'known_sender'],
        'dangerous_contexts': ['unsolicited', 'with_urgency', 'with_fee'],
        'safe_examples': ['Special offer for existing customers', 'Loan offer: Visit your branch'],
        'scam_examples': ['SPECIAL OFFER: Double your money!', 'Limited offer: Send now!'],
    },
}

# Known safe domains — words here are trusted
SAFE_DOMAINS = {
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'whatsapp.com', 'telegram.org', 'youtube.com', 'wikipedia.org',
    'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
    'github.com', 'gitlab.com', 'linkedin.com', 'zoom.us',
    'safaricom.co.ke', 'airtel.co.ke', 'telkom.co.ke',
    'kcbgroup.com', 'equitybank.co.ke', 'coopbank.co.ke', 'absabank.co.ke',
    'kra.go.ke', 'ecitizen.go.ke', 'nssf.go.ke', 'nhif.go.ke',
    'jumia.co.ke', 'kilimall.co.ke', 'carrefour.co.ke',
}


class ContextAwareHybridDetector:
    """
    Hybrid detector combining rules + context analysis + ML.
    Understands that legitimate sites like Google can use words
    that appear in scams when the context is safe.
    """
    
    def __init__(self, rule_detector):
        self.rule_detector = rule_detector
        self.vectorizer = None
        self.classifier = None
        self.is_trained = False
        self.model_metrics = {}
    
    def analyze_context(self, text):
        """
        Analyze the context of a message to determine if words
        that look like scam indicators are actually safe.
        """
        text_lower = text.lower()
        
        context = {
            'has_url': False,
            'url_is_safe': False,
            'has_phone': False,
            'has_pin_request': False,
            'has_urgency': False,
            'has_fee_request': False,
            'has_threat': False,
            'is_bank_notification': False,
            'is_mpesa_transaction': False,
            'is_service_notification': False,
            'is_personal_message': False,
            'is_marketing': False,
            'safe_context_score': 0,
            'danger_signal_score': 0,
        }
        
        # Check URLs and if they're safe
        urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+|www\.[^\s<>"\'{}|\\^`\[\]]+', text_lower)
        if urls:
            context['has_url'] = True
            for url in urls:
                for safe_domain in SAFE_DOMAINS:
                    if safe_domain in url:
                        context['url_is_safe'] = True
                        context['safe_context_score'] += 3
                        break
        
        # Check for phone numbers
        if re.search(r'\b(07|01|2547)\d{8}\b', text_lower):
            context['has_phone'] = True
            context['danger_signal_score'] += 2
        
        # Check for PIN/OTP/password requests
        if re.search(r'(?:send|share|provide|enter|type|give)\s+(?:your\s+)?(?:pin|otp|mpin|password|secret)', text_lower):
            context['has_pin_request'] = True
            context['danger_signal_score'] += 10  # Highest danger
        
        # Check for urgency
        if re.search(r'urgent|immediately|asap|haraka|sasa\s+hivi|right\s+now', text_lower):
            context['has_urgency'] = True
            context['danger_signal_score'] += 5
        
        # Check for fee/money requests
        if re.search(r'pay\s+(?:ksh|kes)\s*\d+|send\s+(?:ksh|kes)\s*\d+|processing\s+fee|registration\s+fee', text_lower):
            context['has_fee_request'] = True
            context['danger_signal_score'] += 6
        
        # Check for threats
        if re.search(r'suspended|blocked|locked|deactivated|closed|terminated|legal\s+action|police\s+case', text_lower):
            context['has_threat'] = True
            context['danger_signal_score'] += 4
        
        # Detect safe contexts
        if re.search(r'(?:kcb|equity|coop|absa|stanbic|ncba)\s*:', text_lower):
            context['is_bank_notification'] = True
            context['safe_context_score'] += 5
        
        if re.search(r'm-pesa\s*:\s*ksh\s*\d|m-pesa\s*:\s*you\s+(?:received|sent)|m-pesa\s*:\s*balance', text_lower):
            context['is_mpesa_transaction'] = True
            context['safe_context_score'] += 5
        
        if re.search(r'(?:data\s+bundle|airtime|subscription|bill|statement)\s+(?:expir|renew|ready|due)', text_lower):
            context['is_service_notification'] = True
            context['safe_context_score'] += 3
        
        if re.search(r'^(?:hi|hello|hey|habari|niaje)\b|(?:prayer|church|meeting|dinner|birthday)', text_lower):
            context['is_personal_message'] = True
            context['safe_context_score'] += 4
        
        if re.search(r'(?:sale|discount|offer|promotion|deal|save)\s+(?:up\s+to|now|today)', text_lower):
            context['is_marketing'] = True
        
        # Check context-dependent words
        for word, info in CONTEXT_DEPENDENT_WORDS.items():
            if word in text_lower:
                if any(ctx in str(context) for ctx in info['safe_contexts']):
                    context['safe_context_score'] += 2
                if any(ctx in str(context) for ctx in info['dangerous_contexts']):
                    context['danger_signal_score'] += 3
        
        return context
    
    def get_context_adjustment(self, context):
        """
        Calculate score adjustment based on context.
        Reduces scam probability for safe contexts,
        increases for dangerous ones.
        """
        adjustment = 0
        
        # Safe context reduces scam probability
        if context['safe_context_score'] >= 8:
            adjustment -= 25
        elif context['safe_context_score'] >= 5:
            adjustment -= 15
        elif context['safe_context_score'] >= 3:
            adjustment -= 8
        
        # Safe URL with legitimate domain
        if context['url_is_safe']:
            adjustment -= 10
        
        # Bank notification context
        if context['is_bank_notification'] and not context['has_pin_request']:
            adjustment -= 20
        
        # M-Pesa transaction context
        if context['is_mpesa_transaction'] and not context['has_pin_request']:
            adjustment -= 20
        
        # Personal message context
        if context['is_personal_message'] and context['danger_signal_score'] < 3:
            adjustment -= 25
        
        # Dangerous signals increase scam probability
        if context['has_pin_request']:
            adjustment += 30
        if context['has_urgency'] and context['has_fee_request']:
            adjustment += 20
        if context['has_threat'] and context['danger_signal_score'] >= 8:
            adjustment += 15
        if context['has_phone'] and context['has_pin_request']:
            adjustment += 20
        
        return adjustment
    
    def predict(self, text, rule_results):
        """
        Context-aware hybrid prediction.
        Combines rules + context analysis + ML.
        """
        # Get rule-based score
        rule_score = rule_results.get('score', 0)
        
        # Analyze context
        context = self.analyze_context(text)
        context_adjustment = self.get_context_adjustment(context)
        
        # Get ML prediction if available
        ml_score = None
        ml_confidence = 0
        
        if self.is_trained and self.vectorizer and self.classifier:
            try:
                X = self.vectorizer.transform([text])
                ml_score = self.classifier.predict_proba(X)[0][1] * 100
                ml_confidence = max(self.model_metrics.values()) if self.model_metrics else 0.7
            except Exception:
                pass
        
        # Combine scores with context adjustment
        if ml_score is not None:
            # 40% rules + 40% ML + 20% context
            final_score = (rule_score * 0.4) + (ml_score * 0.4) + (context_adjustment * 0.2)
            final_score = round(final_score + (context_adjustment * 0.5))
        else:
            # 60% rules + 40% context
            final_score = rule_score + context_adjustment
        
        # Clamp to 0-100
        final_score = max(0, min(100, final_score))
        
        # Determine risk level
        if final_score >= 70:
            risk_level = 'HIGH_RISK'
        elif final_score >= 40:
            risk_level = 'MEDIUM_RISK'
        else:
            risk_level = 'LOW_RISK'
        
        return {
            'final_score': round(final_score, 1),
            'risk_level': risk_level,
            'confidence': ml_confidence if ml_score else 0.8,
            'rule_score': rule_score,
            'ml_score': ml_score,
            'context_adjustment': context_adjustment,
            'context': context,
            'is_ml_enhanced': ml_score is not None,
            'is_context_adjusted': context_adjustment != 0,
        }
    
    def train_from_existing_data(self, training_data_path=None):
        """Train ML model from database reports"""
        from .models import ScamReport
        
        reports = ScamReport.objects.all()
        if reports.count() < 100:
            print(f"⚠️ Only {reports.count()} samples. Need at least 100.")
            return False
        
        texts, labels = [], []
        for report in reports:
            texts.append(report.content)
            labels.append(1 if report.risk_score >= 50 else 0)
        
        self.vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 3), min_df=2, max_df=0.95)
        X_tfidf = self.vectorizer.fit_transform(texts)
        
        models = {
            'logistic': LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42),
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
        }
        
        best_model = None
        best_score = 0
        
        for name, model in models.items():
            scores = cross_val_score(model, X_tfidf, labels, cv=5, scoring='f1')
            avg_score = scores.mean()
            self.model_metrics[name] = avg_score
            
            if avg_score > best_score:
                best_score = avg_score
                best_model = model
                best_model.fit(X_tfidf, labels)
        
        self.classifier = best_model
        self.is_trained = True
        
        print(f"✅ Context-Aware ML trained! Best F1: {best_score:.2%}")
        return True
    
    def save_model(self, path='ml_models/hybrid_model.pkl'):
        """Save trained model"""
        Path('ml_models').mkdir(exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'vectorizer': self.vectorizer,
                'classifier': self.classifier,
                'metrics': self.model_metrics,
                'trained_date': datetime.now().isoformat(),
            }, f)
        print(f"✅ Model saved to {path}")
    
    def load_model(self, path='ml_models/hybrid_model.pkl'):
        """Load trained model"""
        if not Path(path).exists():
            # Try alternative path
            alt_path = Path(__file__).parent / 'ml' / 'models' / 'scam_model.joblib'
            if alt_path.exists():
                self.classifier = joblib.load(alt_path)
                self.is_trained = True
                print(f"✅ Model loaded from {alt_path}")
                return
        
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.vectorizer = data['vectorizer']
            self.classifier = data['classifier']
            self.model_metrics = data['metrics']
            self.is_trained = True
        print(f"✅ Model loaded from {path}")