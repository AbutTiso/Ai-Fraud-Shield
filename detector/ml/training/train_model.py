# detector/ml/training/train_model.py
"""
Enhanced ML Training Pipeline for Scam Detection
Context-aware, dynamically updated, production-ready
"""

import os
import json
import pickle
import re
import numpy as np
from datetime import datetime
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.naive_bayes import MultinomialNB, ComplementNB
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_score, train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
import joblib


class ContextAwareScamDetector:
    """
    ML model for scam detection with context awareness.
    Handles legitimate words in scam contexts vs legitimate contexts.
    Supports continuous retraining from user feedback.
    """
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.best_score = 0
        self.best_model_name = ""
        self.training_history = []
        self.models_dir = Path(__file__).parent.parent / 'models'
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.model_path = self.models_dir / 'scam_model.joblib'
        self.metadata_path = self.models_dir / 'metadata.json'
        self.history_path = self.models_dir / 'training_history.json'
        
        # Load existing history
        self._load_history()
    
    def _load_history(self):
        """Load training history"""
        if self.history_path.exists():
            try:
                with open(self.history_path) as f:
                    self.training_history = json.load(f)
            except:
                self.training_history = []
    
    def _save_history(self, entry):
        """Save training run to history"""
        self.training_history.append(entry)
        # Keep last 50 runs
        self.training_history = self.training_history[-50:]
        with open(self.history_path, 'w') as f:
            json.dump(self.training_history, f, indent=2)
    
    def build_models(self):
        """
        Define multiple models with context-aware feature engineering.
        Uses n-grams (1-4) to capture phrases, not just words.
        """
        models = {
            # Logistic Regression with L2 regularization - good for text
            'LogisticRegression': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=8000,
                    ngram_range=(1, 4),  # Capture phrases like "send money to"
                    stop_words='english',
                    min_df=2,
                    max_df=0.9,
                    sublinear_tf=True,
                    strip_accents='unicode',
                )),
                ('classifier', LogisticRegression(
                    C=0.8,
                    max_iter=3000,
                    class_weight='balanced',
                    random_state=42,
                    solver='lbfgs',
                ))
            ]),
            
            # Calibrated LinearSVC - fast, good for text
            'CalibratedSVC': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=6000,
                    ngram_range=(1, 3),
                    min_df=2,
                    sublinear_tf=True,
                )),
                ('classifier', CalibratedClassifierCV(
                    LinearSVC(C=1.0, class_weight='balanced', random_state=42, max_iter=2000),
                    cv=5, method='sigmoid'
                ))
            ]),
            
            # Complement Naive Bayes - handles imbalanced data well
            'ComplementNB': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=6000,
                    ngram_range=(1, 3),
                    min_df=1,
                    sublinear_tf=True,
                )),
                ('classifier', ComplementNB(alpha=0.1, norm=False))
            ]),
            
            # SGD Classifier - online learning capable
            'SGDClassifier': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=6000,
                    ngram_range=(1, 3),
                    min_df=2,
                    sublinear_tf=True,
                )),
                ('classifier', SGDClassifier(
                    loss='modified_huber',
                    penalty='l2',
                    alpha=0.0001,
                    max_iter=2000,
                    class_weight='balanced',
                    random_state=42,
                    early_stopping=True,
                    validation_fraction=0.1,
                ))
            ]),
            
            # Gradient Boosting - captures complex patterns
            'GradientBoosting': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=4000,
                    ngram_range=(1, 2),
                    min_df=2,
                    sublinear_tf=True,
                )),
                ('classifier', GradientBoostingClassifier(
                    n_estimators=200,
                    max_depth=5,
                    learning_rate=0.05,
                    subsample=0.8,
                    random_state=42,
                ))
            ]),
        }
        return models
    
    def train(self, messages=None, labels=None, sources=None):
        """
        Train the model with context-aware data.
        
        Args:
            messages: List of text messages
            labels: List of labels (1=scam, 0=legitimate)
            sources: Optional list of data sources for tracking
        """
        print("=" * 60)
        print("🧠 TRAINING CONTEXT-AWARE SCAM DETECTION MODEL")
        print("=" * 60)
        
        # Load data
        if messages is None or labels is None:
            messages, labels = self._load_training_data()
        
        # Add context markers to help model distinguish contexts
        messages = self._add_context_markers(messages)
        
        print(f"\n📊 Dataset: {len(messages)} examples")
        print(f"   Scam: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
        print(f"   Legitimate: {len(labels)-sum(labels)} ({(len(labels)-sum(labels))/len(labels)*100:.1f}%)")
        
        # Stratified split for evaluation
        X_train, X_test, y_train, y_test = train_test_split(
            messages, labels, test_size=0.15, random_state=42, stratify=labels
        )
        
        print(f"   Train: {len(X_train)}, Test: {len(X_test)}")
        
        # Try multiple models
        models = self.build_models()
        best_model = None
        best_score = 0
        best_name = ''
        all_results = []
        
        for name, model in models.items():
            print(f"\n🔧 Training {name}...")
            
            try:
                # Stratified cross-validation
                cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
                cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='f1', n_jobs=-1)
                avg_score = cv_scores.mean()
                
                # Also evaluate on test set
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                test_f1 = f1_score(y_test, y_pred)
                test_precision = precision_score(y_test, y_pred)
                test_recall = recall_score(y_test, y_pred)
                
                print(f"   CV F1: {avg_score:.4f} (±{cv_scores.std():.4f})")
                print(f"   Test F1: {test_f1:.4f}, Precision: {test_precision:.4f}, Recall: {test_recall:.4f}")
                
                all_results.append({
                    'name': name,
                    'cv_f1': float(avg_score),
                    'test_f1': float(test_f1),
                    'precision': float(test_precision),
                    'recall': float(test_recall),
                })
                
                if avg_score > best_score:
                    best_score = avg_score
                    best_name = name
                    # Train on full dataset
                    model.fit(messages, labels)
                    best_model = model
                    print(f"   ✅ New best model! ({name})")
                    
            except Exception as e:
                print(f"   ❌ Failed: {e}")
        
        # Store best model
        self.model = best_model
        self.best_score = best_score
        self.best_model_name = best_name
        
        # Save everything
        self.save_model()
        
        # Record training history
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'model_name': best_name,
            'f1_score': float(best_score),
            'num_samples': len(messages),
            'num_scam': int(sum(labels)),
            'num_legit': int(len(labels) - sum(labels)),
            'all_results': all_results,
            'sources': sources or ['training_data'],
        }
        self._save_history(history_entry)
        
        # Final summary
        print("\n" + "=" * 60)
        print(f"🏆 BEST MODEL: {best_name}")
        print(f"📊 CV F1 Score: {best_score:.4f} ({best_score*100:.1f}%)")
        print(f"📈 Training history: {len(self.training_history)} runs")
        print("=" * 60)
        
        return self.model
    
    def _add_context_markers(self, messages):
        """
        Add context markers to help model understand word usage.
        Words like 'verify' are legitimate in bank contexts but suspicious in unsolicited SMS.
        """
        enhanced = []
        for msg in messages:
            msg_lower = msg.lower()
            markers = []
            
            # Context detection
            if re.search(r'(?:bank|kcb|equity|coop|absa|stanbic|ncba)\s*:', msg_lower):
                markers.append('BANK_NOTIFICATION')
            if re.search(r'm-pesa|mpesa|safaricom', msg_lower):
                markers.append('MPESA_CONTEXT')
            if re.search(r'http[s]?://', msg_lower):
                markers.append('HAS_URL')
            if re.search(r'\b(07|01|2547)\d{8}\b', msg_lower):
                markers.append('HAS_PHONE')
            if re.search(r'urgent|immediately|asap|haraka', msg_lower):
                markers.append('URGENCY')
            if re.search(r'pin|otp|mpin|password|siri', msg_lower):
                markers.append('SENSITIVE_REQUEST')
            if re.search(r'\b(ksh|kes)\s*\d+', msg_lower):
                markers.append('MONEY_AMOUNT')
            if re.search(r'won|winner|congratulations|prize|lotto', msg_lower):
                markers.append('PRIZE_LANGUAGE')
            if re.search(r'(?:loan|mkopo|fuliza|m-shwari)', msg_lower):
                markers.append('LOAN_CONTEXT')
            
            # Add markers as prefix (model learns these features)
            if markers:
                enhanced.append(f"[{'|'.join(markers)}] {msg}")
            else:
                enhanced.append(f"[GENERAL] {msg}")
        
        return enhanced
    
    def _load_training_data(self):
        """Load training data from database and hardcoded examples"""
        from .prepare_data import get_hardcoded_training_data, extract_training_data_from_database
        
        messages = []
        labels = []
        
        # Load from database
        db_messages, db_labels = extract_training_data_from_database()
        messages.extend(db_messages)
        labels.extend(db_labels)
        
        # Load hardcoded examples
        hc_messages, hc_labels = get_hardcoded_training_data()
        messages.extend(hc_messages)
        labels.extend(hc_labels)
        
        # Load user feedback corrections
        fb_messages, fb_labels = self._load_feedback_data()
        messages.extend(fb_messages)
        labels.extend(fb_labels)
        
        # Balance classes
        scam_count = sum(labels)
        legit_count = len(labels) - scam_count
        
        if legit_count > scam_count * 1.5:
            # Oversample scam examples
            scam_msgs = [m for m, l in zip(messages, labels) if l == 1]
            oversample_factor = min(3, legit_count // max(1, scam_count))
            for _ in range(oversample_factor - 1):
                messages.extend(scam_msgs)
                labels.extend([1] * len(scam_msgs))
        
        print(f"   Loaded {len(messages)} total (from DB + hardcoded + feedback)")
        return messages, labels
    
    def _load_feedback_data(self):
        """Load user feedback corrections for retraining"""
        feedback_path = Path(__file__).parent.parent.parent / 'data' / 'feedback_data.json'
        messages = []
        labels = []
        
        if feedback_path.exists():
            try:
                with open(feedback_path) as f:
                    feedbacks = json.load(f)
                
                for fb in feedbacks:
                    if fb.get('original_text') and fb.get('user_verdict'):
                        if fb['user_verdict'] == 'scam':
                            messages.append(fb['original_text'])
                            labels.append(1)
                        elif fb['user_verdict'] == 'legitimate':
                            messages.append(fb['original_text'])
                            labels.append(0)
                
                if messages:
                    print(f"   Loaded {len(messages)} feedback corrections")
            except Exception:
                pass
        
        return messages, labels
    
    def predict(self, text):
        """Predict with confidence scoring"""
        if self.model is None:
            self.load_model()
        
        if self.model is None:
            return {"error": "Model not trained", "ml_score": 50}
        
        cleaned = self._add_context_markers([text])[0]
        
        try:
            proba = self.model.predict_proba([cleaned])[0]
            scam_probability = proba[1] if len(proba) > 1 else proba[0]
        except:
            try:
                decision = self.model.decision_function([cleaned])[0]
                scam_probability = 1 / (1 + np.exp(-decision))
            except:
                prediction = self.model.predict([cleaned])[0]
                scam_probability = float(prediction)
        
        ml_score = round(scam_probability * 100, 1)
        
        # Confidence thresholds
        if ml_score >= 80:
            risk_level = "HIGH RISK"
            is_scam = True
        elif ml_score >= 60:
            risk_level = "MEDIUM RISK"
            is_scam = True
        elif ml_score >= 40:
            risk_level = "LOW RISK"
            is_scam = False
        elif ml_score >= 20:
            risk_level = "SAFE"
            is_scam = False
        else:
            risk_level = "SAFE"
            is_scam = False
        
        return {
            "ml_score": ml_score,
            "ml_risk_level": risk_level,
            "ml_is_scam": is_scam,
            "ml_confidence": round(self.best_score * 100, 1),
            "model_name": self.best_model_name,
        }
    
    def save_model(self):
        """Save model and metadata"""
        if self.model:
            joblib.dump(self.model, self.model_path)
            print(f"   💾 Model saved to {self.model_path}")
        
        metadata = {
            'model_name': self.best_model_name,
            'f1_score': float(self.best_score),
            'training_runs': len(self.training_history),
            'last_trained': datetime.now().isoformat(),
        }
        with open(self.metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def load_model(self):
        """Load model from disk"""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                if self.metadata_path.exists():
                    with open(self.metadata_path) as f:
                        meta = json.load(f)
                        self.best_score = meta.get('f1_score', 0)
                        self.best_model_name = meta.get('model_name', '')
                return True
            except Exception as e:
                print(f"Model load error: {e}")
        return False
    
    def get_training_stats(self):
        """Get training history statistics"""
        if not self.training_history:
            return {'runs': 0, 'latest_score': 0, 'improvement': 0}
        
        latest = self.training_history[-1]
        first = self.training_history[0] if len(self.training_history) > 1 else latest
        
        return {
            'runs': len(self.training_history),
            'latest_score': round(latest.get('f1_score', 0) * 100, 1),
            'latest_model': latest.get('model_name', ''),
            'improvement': round((latest.get('f1_score', 0) - first.get('f1_score', 0)) * 100, 1),
            'total_samples': latest.get('num_samples', 0),
        }


def quick_train():
    """Quick training for management command"""
    trainer = ContextAwareScamDetector()
    model = trainer.train()
    
    # Quick test
    tests = [
        "URGENT: Your M-Pesa suspended. Send PIN to verify.",
        "Hi mom, can you pick up bread on your way home?",
        "Congratulations you won Ksh 500000! Send 1000 to claim.",
        "Your KCB salary of Ksh 50000 has been credited.",
    ]
    
    print("\n🧪 Quick Test:")
    for msg in tests:
        result = trainer.predict(msg)
        print(f"   {result['ml_risk_level']:12s} ({result['ml_score']:5.1f}%) | {msg[:60]}")
    
    return trainer


if __name__ == "__main__":
    quick_train()