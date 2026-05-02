# detector/ml_trainer.py
"""
ML Model Training Pipeline for Fraud Detection
Trains models using existing scam reports from database
"""

import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.pipeline import Pipeline
import joblib

# Django setup for accessing database
import django
import os
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
                texts.append(report.content)
                # Label: 1 = scam (high risk), 0 = legitimate
                label = 1 if report.risk_score >= 40 else 0
                labels.append(label)
        
        print(f"✅ Loaded {len(texts)} samples")
        print(f"   Scam samples: {sum(labels)}")
        print(f"   Legitimate samples: {len(labels) - sum(labels)}")
        
        return texts, labels
    
    def train_sms_model(self, texts, labels):
        """
        Train SMS scam detection model
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
        
        print("✅ Model trained!")
        print(f"   Accuracy: {accuracy:.2%}")
        print(f"   F1 Score: {f1:.2%}")
        
        # Store model
        self.models['sms'] = pipeline
        self.model_metrics['sms'] = {
            'accuracy': accuracy,
            'f1_score': f1,
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        # Print classification report
        print("\n📊 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Scam']))
        
        return pipeline
    
    def train_url_model(self, urls, labels):
        """
        Train URL phishing detection model using character-level features
        """
        print("\n" + "="*60)
        print("🔗 Training URL Phishing Detection Model")
        print("="*60)
        
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
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
            'MLP Neural Net': MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42)
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
        
        for name, clf in classifiers.items():
            clf.fit(X_train, y_train)
            y_pred = clf.predict(X_test)
            score = accuracy_score(y_test, y_pred)
            results[name] = score
            
            if score > best_score:
                best_score = score
                best_model = clf
                best_model_name = name
        
        print(f"✅ Best model: {best_model_name}")
        print(f"   Accuracy: {best_score:.2%}")
        
        for name, score in results.items():
            print(f"   {name}: {score:.2%}")
        
        # Store ensemble
        self.models['ensemble'] = {
            'vectorizer': vectorizer,
            'classifier': best_model,
            'name': best_model_name
        }
        
        self.model_metrics['ensemble'] = {
            'accuracy': best_score,
            'model_name': best_model_name,
            'results': results
        }
        
        return best_model
    
    def save_models(self, models_dir='ml_models'):
        """
        Save all trained models to disk
        """
        os.makedirs(models_dir, exist_ok=True)
        
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
        
        # Save metrics
        metrics_path = os.path.join(models_dir, 'model_metrics.json')
        import json
        with open(metrics_path, 'w') as f:
            # Convert non-serializable objects
            serializable_metrics = {}
            for k, v in self.model_metrics.items():
                serializable_metrics[k] = {k2: v2 for k2, v2 in v.items() if not callable(v2)}
            json.dump(serializable_metrics, f, indent=2, default=str)
        
        print(f"\n✅ Models saved to '{models_dir}/'")
        
    def load_models(self, models_dir='ml_models'):
        """
        Load trained models from disk
        """
        import json
        
        # Load SMS model
        sms_path = os.path.join(models_dir, 'sms_model.pkl')
        if os.path.exists(sms_path):
            with open(sms_path, 'rb') as f:
                self.models['sms'] = pickle.load(f)
            print("✅ Loaded SMS model")
        
        # Load URL model
        url_path = os.path.join(models_dir, 'url_model.pkl')
        if os.path.exists(url_path):
            with open(url_path, 'rb') as f:
                self.models['url'] = pickle.load(f)
            print("✅ Loaded URL model")
        
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
                'classifier': classifier
            }
            print("✅ Loaded Ensemble model")
        
        # Load metrics
        metrics_path = os.path.join(models_dir, 'model_metrics.json')
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r') as f:
                self.model_metrics = json.load(f)
            print("✅ Loaded model metrics")
    
    def predict_sms(self, text):
        """
        Predict if SMS is scam using trained model
        """
        if 'sms' not in self.models:
            print("⚠️ SMS model not loaded. Train or load models first.")
            return None
        
        model = self.models['sms']
        proba = model.predict_proba([text])[0]
        
        return {
            'is_scam': proba[1] >= 0.5,
            'confidence': proba[1],
            'scam_probability': proba[1] * 100,
            'legitimate_probability': proba[0] * 100
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
        
        return {
            'is_phishing': proba[1] >= 0.5,
            'confidence': proba[1],
            'phishing_probability': proba[1] * 100
        }


def run_training():
    """
    Main training function - call this from Django management command
    """
    print("\n" + "="*70)
    print("🚀 AI FRAUD SHIELD - ML MODEL TRAINING")
    print("="*70)
    
    trainer = FraudMLTrainer()
    
    # Load data
    texts, labels = trainer.load_training_data()
    
    if texts is None:
        print("\n❌ Not enough data for training. Collect more scam reports first.")
        print("   Minimum required: 100 samples")
        return
    
    # Train models
    trainer.train_sms_model(texts, labels)
    
    # For URL training, we need URL-specific data
    # This would require collecting URLs separately
    
    # Train ensemble
    trainer.train_ensemble_model(texts, labels)
    
    # Save models
    trainer.save_models()
    
    print("\n" + "="*70)
    print("✅ TRAINING COMPLETE!")
    print("="*70)
    
    return trainer


if __name__ == "__main__":
    run_training()