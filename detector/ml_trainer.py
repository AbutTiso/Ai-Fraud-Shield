# detector/ml_trainer.py
"""
ML Model Training Pipeline for Fraud Detection
Trains models using existing scam reports from database
"""

import os
import sys
import pickle
import json
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
import joblib

# Django setup for accessing database
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fraudshield.settings')
django.setup()

from detector.models import ScamReport


class FraudMLTrainer:
    """
    Train ML models for scam detection using existing data
    """
    
    def __init__(self):
        self.models = {}
        self.vectorizers = {}
        self.model_metrics = {}
        self.training_date = datetime.now()
        self.training_data_size = 0
        
    def load_training_data(self, min_samples=100):
        """
        Load data from database
        Returns: X (texts), y (labels)
        """
        reports = ScamReport.objects.all()
        
        if reports.count() < min_samples:
            print(f"⚠️ Only {reports.count()} samples. Need at least {min_samples} for reliable ML.")
            print("   Continue collecting scam reports first.")
            return None, None
        
        texts = []
        labels = []
        
        for report in reports:
            if report.content and len(report.content) > 10:
                texts.append(report.content[:2000])  # Limit length for performance
                # Label: 1 = scam (high risk), 0 = legitimate
                label = 1 if report.risk_score >= 40 else 0
                labels.append(label)
        
        self.training_data_size = len(texts)
        
        print(f"✅ Loaded {len(texts)} samples")
        print(f"   Scam samples: {sum(labels)}")
        print(f"   Legitimate samples: {len(labels) - sum(labels)}")
        
        return texts, labels
    
    def load_training_data_with_validation(self, min_samples=100, validation_split=0.15):
        """
        Load data with validation split for better accuracy measurement
        """
        reports = ScamReport.objects.all()
        
        if reports.count() < min_samples:
            print(f"⚠️ Only {reports.count()} samples. Need at least {min_samples} for reliable ML.")
            return None, None, None, None, None, None
        
        texts = []
        labels = []
        
        for report in reports:
            if report.content and len(report.content) > 10:
                texts.append(report.content[:2000])
                label = 1 if report.risk_score >= 40 else 0
                labels.append(label)
        
        # Split into train/validation/test
        X_temp, X_test, y_temp, y_test = train_test_split(
            texts, labels, test_size=0.15, random_state=42, stratify=labels
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=validation_split, random_state=42, stratify=y_temp
        )
        
        print(f"✅ Loaded {len(texts)} samples")
        print(f"   Train: {len(X_train)} | Validation: {len(X_val)} | Test: {len(X_test)}")
        print(f"   Scam samples: {sum(labels)} | Legitimate: {len(labels) - sum(labels)}")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def train_sms_model(self, texts, labels):
        """
        Train SMS scam detection model with cross-validation
        """
        print("\n" + "="*60)
        print("📱 Training SMS Scam Detection Model")
        print("="*60)
        
        # Create pipeline with TF-IDF and Random Forest
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 3),
                min_df=2,
                max_df=0.95,
                stop_words='english'
            )),
            ('classifier', RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train
        pipeline.fit(X_train, y_train)
        
        # Evaluate
        y_pred = pipeline.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        
        print("✅ Model trained!")
        print(f"   Accuracy: {accuracy:.2%}")
        print(f"   F1 Score: {f1:.2%}")
        print(f"   Precision: {precision:.2%}")
        print(f"   Recall: {recall:.2%}")
        
        # Cross-validation
        cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring='f1')
        print(f"   5-Fold CV F1: {cv_scores.mean():.2%} (+/- {cv_scores.std() * 2:.2%})")
        
        # Store model
        self.models['sms'] = pipeline
        self.model_metrics['sms'] = {
            'accuracy': accuracy,
            'f1_score': f1,
            'precision': precision,
            'recall': recall,
            'cv_f1_mean': cv_scores.mean(),
            'cv_f1_std': cv_scores.std(),
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        # Print classification report
        print("\n📊 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Scam']))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\n📊 Confusion Matrix:")
        print(f"   True Negatives: {cm[0,0]} | False Positives: {cm[0,1]}")
        print(f"   False Negatives: {cm[1,0]} | True Positives: {cm[1,1]}")
        
        return pipeline
    
    def train_url_model(self, urls, labels):
        """
        Train URL phishing detection model using character-level features
        """
        print("\n" + "="*60)
        print("🔗 Training URL Phishing Detection Model")
        print("="*60)
        
        if len(urls) < 50:
            print("⚠️ Not enough URL samples for training. Need at least 50.")
            return None
        
        # Character-level features for URLs
        pipeline = Pipeline([
            ('char_vector', CountVectorizer(
                analyzer='char',
                ngram_range=(3, 5),
                max_features=1000
            )),
            ('classifier', GradientBoostingClassifier(
                n_estimators=100,
                random_state=42
            ))
        ])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            urls, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train
        pipeline.fit(X_train, y_train)
        
        # Evaluate
        y_pred = pipeline.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        print("✅ Model trained!")
        print(f"   Accuracy: {accuracy:.2%}")
        print(f"   F1 Score: {f1:.2%}")
        
        self.models['url'] = pipeline
        self.model_metrics['url'] = {
            'accuracy': accuracy,
            'f1_score': f1,
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        return pipeline
    
    def train_ensemble_model(self, texts, labels):
        """
        Train ensemble model combining multiple algorithms
        """
        print("\n" + "="*60)
        print("🤖 Training Ensemble Model")
        print("="*60)
        
        # Multiple classifiers
        classifiers = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1),
            'MLP Neural Net': MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42, early_stopping=True)
        }
        
        # TF-IDF vectorizer
        vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
        X = vectorizer.fit_transform(texts)
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        results = {}
        best_model = None
        best_score = 0
        best_model_name = ""
        
        for name, clf in classifiers.items():
            print(f"   Training {name}...")
            clf.fit(X_train, y_train)
            y_pred = clf.predict(X_test)
            score = f1_score(y_test, y_pred)
            acc = accuracy_score(y_test, y_pred)
            results[name] = {'f1': score, 'accuracy': acc}
            
            if score > best_score:
                best_score = score
                best_model = clf
                best_model_name = name
        
        print(f"\n✅ Best model: {best_model_name}")
        print(f"   F1 Score: {best_score:.2%}")
        
        for name, metrics in results.items():
            print(f"   {name}: F1={metrics['f1']:.2%}, Acc={metrics['accuracy']:.2%}")
        
        # Store ensemble
        self.models['ensemble'] = {
            'vectorizer': vectorizer,
            'classifier': best_model,
            'name': best_model_name
        }
        
        self.model_metrics['ensemble'] = {
            'f1_score': best_score,
            'model_name': best_model_name,
            'results': results
        }
        
        return best_model
    
    def evaluate_with_thresholds(self, model, X_test, y_test):
        """
        Evaluate model with different confidence thresholds
        """
        print("\n📊 CONFIDENCE THRESHOLD ANALYSIS")
        print("-" * 50)
        
        # Get prediction probabilities
        y_proba = model.predict_proba(X_test)[:, 1]
        
        thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
        
        best_threshold = 0.5
        best_f1 = 0
        
        for threshold in thresholds:
            y_pred = (y_proba >= threshold).astype(int)
            
            # Calculate metrics
            tn = np.sum((y_pred == 0) & (y_test == 0))
            fp = np.sum((y_pred == 1) & (y_test == 0))
            fn = np.sum((y_pred == 0) & (y_test == 1))
            tp = np.sum((y_pred == 1) & (y_test == 1))
            
            accuracy = (tp + tn) / len(y_test) if len(y_test) > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold
            
            print(f"\nThreshold: {threshold:.1f}")
            print(f"  Accuracy: {accuracy:.2%} | F1: {f1:.2%}")
            print(f"  False Positives: {fp} ({false_positive_rate:.2%})")
            print(f"  False Negatives: {fn}")
            print(f"  Precision: {precision:.2%} | Recall: {recall:.2%}")
        
        print(f"\n🎯 Best threshold: {best_threshold:.1f} (F1: {best_f1:.2%})")
        return best_threshold
    
    def save_models(self, models_dir='ml_models'):
        """
        Save all trained models to disk
        """
        os.makedirs(models_dir, exist_ok=True)
        
        # Save each model
        for model_name, model in self.models.items():
            if model_name == 'ensemble':
                # Save ensemble separately
                filepath = os.path.join(models_dir, f'{model_name}_vectorizer.pkl')
                with open(filepath, 'wb') as f:
                    pickle.dump(model['vectorizer'], f)
                
                filepath = os.path.join(models_dir, f'{model_name}_classifier.pkl')
                with open(filepath, 'wb') as f:
                    pickle.dump(model['classifier'], f)
            else:
                filepath = os.path.join(models_dir, f'{model_name}_model.pkl')
                with open(filepath, 'wb') as f:
                    pickle.dump(model, f)
        
        # Save metrics with full metadata
        metadata = {
            'model_metrics': self.model_metrics,
            'training_date': self.training_date.isoformat(),
            'training_samples': self.training_data_size,
            'models_trained': list(self.models.keys()),
            'version': self.training_date.strftime("%Y%m%d_%H%M%S")
        }
        
        metrics_path = os.path.join(models_dir, 'model_metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
        
        print(f"\n✅ Models saved to '{models_dir}/'")
        print(f"   Models: {', '.join(self.models.keys())}")
        
    def load_models(self, models_dir='ml_models'):
        """
        Load trained models from disk
        """
        loaded_count = 0
        
        # Load SMS model
        sms_path = os.path.join(models_dir, 'sms_model.pkl')
        if os.path.exists(sms_path):
            with open(sms_path, 'rb') as f:
                self.models['sms'] = pickle.load(f)
            print("✅ Loaded SMS model")
            loaded_count += 1
        
        # Load URL model
        url_path = os.path.join(models_dir, 'url_model.pkl')
        if os.path.exists(url_path):
            with open(url_path, 'rb') as f:
                self.models['url'] = pickle.load(f)
            print("✅ Loaded URL model")
            loaded_count += 1
        
        # Load ensemble
        ensemble_vec_path = os.path.join(models_dir, 'ensemble_vectorizer.pkl')
        ensemble_clf_path = os.path.join(models_dir, 'ensemble_classifier.pkl')
        if os.path.exists(ensemble_vec_path) and os.path.exists(ensemble_clf_path):
            with open(ensemble_vec_path, 'rb') as f:
                vectorizer = pickle.load(f)
            with open(ensemble_clf_path, 'rb') as f:
                classifier = pickle.load(f)
            self.models['ensemble'] = {
                'vectorizer': vectorizer,
                'classifier': classifier,
                'name': 'Loaded Ensemble'
            }
            print("✅ Loaded Ensemble model")
            loaded_count += 1
        
        # Load metrics
        metrics_path = os.path.join(models_dir, 'model_metrics.json')
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r') as f:
                metadata = json.load(f)
                self.model_metrics = metadata.get('model_metrics', {})
                if 'training_date' in metadata:
                    self.training_date = datetime.fromisoformat(metadata['training_date'])
            print("✅ Loaded model metrics")
        
        if loaded_count == 0:
            print("⚠️ No models found. Train models first.")
            return False
        
        print(f"✅ Total {loaded_count} model(s) loaded")
        return True
    
    def predict_sms(self, text):
        """
        Predict if SMS is scam using trained model
        """
        if 'sms' not in self.models:
            print("⚠️ SMS model not loaded. Train or load models first.")
            return None
        
        model = self.models['sms']
        proba = model.predict_proba([text[:2000]])[0]  # Limit text length
        
        is_scam = proba[1] >= 0.5
        confidence = proba[1] if is_scam else proba[0]
        
        return {
            'is_scam': is_scam,
            'confidence': float(confidence),
            'scam_probability': float(proba[1] * 100),
            'legitimate_probability': float(proba[0] * 100),
            'prediction': 'SCAM' if is_scam else 'LEGITIMATE'
        }
    
    def predict_url(self, url):
        """
        Predict if URL is phishing using trained model
        """
        if 'url' not in self.models:
            print("⚠️ URL model not loaded. Train or load models first.")
            return None
        
        model = self.models['url']
        proba = model.predict_proba([url])[0]
        
        is_phishing = proba[1] >= 0.5
        
        return {
            'is_phishing': is_phishing,
            'confidence': float(proba[1] if is_phishing else proba[0]),
            'phishing_probability': float(proba[1] * 100),
            'legitimate_probability': float(proba[0] * 100),
            'prediction': 'PHISHING' if is_phishing else 'SAFE'
        }
    
    def predict_ensemble(self, text):
        """
        Predict using ensemble model (if available)
        """
        if 'ensemble' not in self.models:
            print("⚠️ Ensemble model not loaded. Train or load models first.")
            return None
        
        ensemble = self.models['ensemble']
        vectorizer = ensemble['vectorizer']
        classifier = ensemble['classifier']
        
        X = vectorizer.transform([text[:2000]])
        proba = classifier.predict_proba(X)[0]
        
        is_scam = proba[1] >= 0.5
        
        return {
            'is_scam': is_scam,
            'confidence': float(proba[1] if is_scam else proba[0]),
            'scam_probability': float(proba[1] * 100),
            'legitimate_probability': float(proba[0] * 100),
            'model_used': ensemble.get('name', 'Ensemble'),
            'prediction': 'SCAM' if is_scam else 'LEGITIMATE'
        }


def run_training():
    """
    Main training function - call this from Django management command
    """
    print("\n" + "="*70)
    print("🚀 AI FRAUD SHIELD - ML MODEL TRAINING")
    print("="*70)
    print(f"📅 Training Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    trainer = FraudMLTrainer()
    
    # Load data with validation
    X_train, X_val, X_test, y_train, y_val, y_test = trainer.load_training_data_with_validation()
    
    if X_train is None:
        print("\n❌ Not enough data for training. Collect more scam reports first.")
        print("   Minimum required: 100 samples")
        return None
    
    # Train SMS model
    sms_model = trainer.train_sms_model(X_train + X_val + X_test, y_train + y_val + y_test)
    
    # Evaluate with thresholds
    if sms_model:
        # Use test set for final evaluation
        X_test_actual, _, y_test_actual, _ = train_test_split(
            X_test, y_test, test_size=0.5, random_state=42
        ) if len(X_test) > 0 else (X_test, y_test)
        
        trainer.evaluate_with_thresholds(sms_model, X_test_actual, y_test_actual)
    
    # Train ensemble
    trainer.train_ensemble_model(X_train + X_val + X_test, y_train + y_val + y_test)
    
    # Save models
    trainer.save_models()
    
    print("\n" + "="*70)
    print("✅ TRAINING COMPLETE!")
    print("="*70)
    
    # Print summary
    print("\n📊 Model Summary:")
    for model_name, metrics in trainer.model_metrics.items():
        print(f"\n   {model_name.upper()}:")
        for metric, value in metrics.items():
            if isinstance(value, float):
                print(f"      {metric}: {value:.2%}")
            else:
                print(f"      {metric}: {value}")
    
    return trainer


def quick_test():
    """
    Quick test function to verify models work
    """
    print("\n" + "="*70)
    print("🧪 QUICK MODEL TEST")
    print("="*70)
    
    trainer = FraudMLTrainer()
    
    if not trainer.load_models():
        print("❌ No models found. Run training first.")
        return
    
    # Test SMS
    test_sms = "URGENT! Your M-Pesa account has been suspended. Click https://bit.ly/verify to reactivate now!"
    result = trainer.predict_sms(test_sms)
    
    if result:
        print("\n📱 SMS Test:")
        print(f"   Text: {test_sms[:80]}...")
        print(f"   Prediction: {result['prediction']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Scam Probability: {result['scam_probability']:.1f}%")
    
    # Test ensemble
    ensemble_result = trainer.predict_ensemble(test_sms)
    if ensemble_result:
        print("\n🤖 Ensemble Test:")
        print(f"   Prediction: {ensemble_result['prediction']}")
        print(f"   Confidence: {ensemble_result['confidence']:.2%}")
        print(f"   Model Used: {ensemble_result.get('model_used', 'Unknown')}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        quick_test()
    else:
        run_training()