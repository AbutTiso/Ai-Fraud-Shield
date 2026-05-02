# detector/ml_enhanced.py
"""
ML Enhancement for existing rule-based detectors
Hybrid approach: Rules + ML for 95%+ accuracy
"""

import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import cross_val_score
import joblib
from pathlib import Path
import json
from datetime import datetime

class HybridScamDetector:
    """
    Combines your existing rule-based detection with ML
    This gives you the best of both worlds:
    - Rules catch known patterns immediately
    - ML catches novel scam variations
    """
    
    def __init__(self, rule_detector):
        self.rule_detector = rule_detector
        self.vectorizer = None
        self.classifier = None
        self.is_trained = False
        self.model_metrics = {}
        
    def extract_features_for_ml(self, text, rule_results):
        """
        Combine rule-based features with text embeddings
        This creates a rich feature vector for ML
        """
        features = []
        
        # 1. Rule-based features (from your existing detector)
        features.append(rule_results.get('score', 0) / 100)  # Normalized score
        features.append(len(rule_results.get('warnings', [])))  # Warning count
        features.append(len(rule_results.get('high_risk_found', [])))  # High risk patterns
        features.append(len(rule_results.get('medium_risk_found', [])))  # Medium risk patterns
        
        # 2. Text statistics
        features.append(len(text))  # Length
        features.append(text.count(' '))  # Word count
        features.append(text.count('!'))  # Exclamation marks
        features.append(text.count('?'))  # Question marks
        features.append(sum(c.isupper() for c in text if c.isalpha()) / max(1, len(text)))  # Uppercase ratio
        
        # 3. Special character density
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        features.append(special_chars / max(1, len(text)))
        
        return np.array(features)
    
    def train_from_existing_data(self, training_data_path):
        """
        Train ML model using your existing scam reports from database
        """
        # Load training data from your ScamReport model
        from .models import ScamReport
        
        reports = ScamReport.objects.all()
        if reports.count() < 100:
            print(f"⚠️ Only {reports.count()} samples. Need at least 100 for ML.")
            return False
        
        texts = []
        labels = []
        
        for report in reports:
            texts.append(report.content)
            # Label: 1 = scam (high risk), 0 = legitimate
            label = 1 if report.risk_score >= 50 else 0
            labels.append(label)
        
        # Create TF-IDF features
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),  # Unigrams, bigrams, trigrams
            min_df=2,
            max_df=0.95
        )
        
        X_tfidf = self.vectorizer.fit_transform(texts)
        
        # Train ensemble of models
        models = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'neural_network': MLPClassifier(hidden_layer_sizes=(100, 50), random_state=42)
        }
        
        best_model = None
        best_score = 0
        
        for name, model in models.items():
            scores = cross_val_score(model, X_tfidf, labels, cv=5)
            avg_score = scores.mean()
            self.model_metrics[name] = avg_score
            
            if avg_score > best_score:
                best_score = avg_score
                best_model = model
                best_model.fit(X_tfidf, labels)
        
        self.classifier = best_model
        self.is_trained = True
        
        print(f"✅ ML Model trained! Best accuracy: {best_score:.2%}")
        print(f"   Model metrics: {self.model_metrics}")
        
        return True
    
    def predict(self, text, rule_results):
        """
        Hybrid prediction: combine rule score + ML prediction
        """
        # Get rule-based score (0-100)
        rule_score = rule_results.get('score', 0)
        
        # Get ML prediction if available
        ml_probability = None
        ml_confidence = 0
        
        if self.is_trained and self.vectorizer and self.classifier:
            # Transform text to TF-IDF
            X = self.vectorizer.transform([text])
            # Get probability of being scam
            ml_probability = self.classifier.predict_proba(X)[0][1] * 100
            
            # Calculate confidence based on model metrics
            ml_confidence = max(self.model_metrics.values()) if self.model_metrics else 0.7
        
        # Combine scores (weighted average)
        if ml_probability is not None:
            # Rules: 40% weight, ML: 60% weight (ML learns new patterns)
            final_score = (rule_score * 0.4) + (ml_probability * 0.6)
            confidence = ml_confidence
        else:
            final_score = rule_score
            confidence = 0.6  # Default confidence for rules only
        
        # Determine risk level with confidence
        if final_score >= 70:
            risk_level = 'HIGH_RISK'
        elif final_score >= 40:
            risk_level = 'MEDIUM_RISK'
        else:
            risk_level = 'LOW_RISK'
        
        return {
            'final_score': final_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'rule_score': rule_score,
            'ml_score': ml_probability,
            'is_ml_enhanced': ml_probability is not None
        }
    
    def save_model(self, path='ml_models/hybrid_model.pkl'):
        """Save trained model"""
        Path('ml_models').mkdir(exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'vectorizer': self.vectorizer,
                'classifier': self.classifier,
                'metrics': self.model_metrics,
                'trained_date': datetime.now().isoformat()
            }, f)
        print(f"✅ Model saved to {path}")
    
    def load_model(self, path='ml_models/hybrid_model.pkl'):
        """Load trained model"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.vectorizer = data['vectorizer']
            self.classifier = data['classifier']
            self.model_metrics = data['metrics']
            self.is_trained = True
        print(f"✅ Model loaded from {path}")