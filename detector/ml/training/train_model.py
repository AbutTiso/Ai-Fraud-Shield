# detector/ml/training/train_model.py
import os
import pickle
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from .prepare_data import SMSDataPreparer, get_hardcoded_training_data, extract_training_data_from_database
import joblib

class ScamDetectionModel:
    """
    ML model for SMS scam detection using scikit-learn
    Supports multiple algorithms with automatic best model selection
    """
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.best_score = 0
        self.best_model_name = ""
        self.model_path = 'detector/ml/models/scam_model.joblib'
        self.vectorizer_path = 'detector/ml/models/vectorizer.pkl'
        
    def build_models(self):
        """Define multiple models to try"""
        models = {
            'LogisticRegression': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=5000,
                    ngram_range=(1, 3),
                    stop_words='english',
                    min_df=2,
                    max_df=0.9,
                    strip_accents='unicode'
                )),
                ('classifier', LogisticRegression(
                    C=1.0,
                    max_iter=1000,
                    class_weight='balanced',
                    random_state=42
                ))
            ]),
            'LinearSVC': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=5000,
                    ngram_range=(1, 2),
                    stop_words='english',
                    min_df=2
                )),
                ('classifier', LinearSVC(
                    C=1.0,
                    class_weight='balanced',
                    random_state=42,
                    max_iter=2000
                ))
            ]),
            'MultinomialNB': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=5000,
                    ngram_range=(1, 2),
                    stop_words='english'
                )),
                ('classifier', MultinomialNB(alpha=0.1))
            ]),
            'RandomForest': Pipeline([
                ('vectorizer', TfidfVectorizer(
                    max_features=3000,
                    ngram_range=(1, 2),
                    stop_words='english'
                )),
                ('classifier', RandomForestClassifier(
                    n_estimators=200,
                    max_depth=20,
                    class_weight='balanced',
                    random_state=42,
                    n_jobs=-1
                ))
            ]),
        }
        return models
    
    def train(self, messages=None, labels=None):
        """
        Train the model on provided data or hardcoded examples
        
        Args:
            messages: List of text messages
            labels: List of labels (1=scam, 0=legitimate)
        """
        print("=" * 60)
        print("🧠 TRAINING SCAM DETECTION MODEL")
        print("=" * 60)
        
        # Load data
        if messages is None or labels is None:
            db_messages, db_labels = extract_training_data_from_database()
            hc_messages, hc_labels = get_hardcoded_training_data()
            
            messages = db_messages + hc_messages
            labels = db_labels + hc_labels
        
        print(f"\n📊 Dataset: {len(messages)} examples")
        print(f"   Scam: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
        print(f"   Legitimate: {len(labels)-sum(labels)} ({(len(labels)-sum(labels))/len(labels)*100:.1f}%)")
        
        # Try multiple models
        models = self.build_models()
        
        for name, model in models.items():
            print(f"\n🔧 Training {name}...")
            
            # Cross-validation
            try:
                cv_scores = cross_val_score(model, messages, labels, cv=5, scoring='f1', n_jobs=-1)
                avg_score = cv_scores.mean()
                
                print(f"   Cross-validation F1 scores: {[f'{s:.3f}' for s in cv_scores]}")
                print(f"   Average F1: {avg_score:.4f}")
                
                if avg_score > self.best_score:
                    self.best_score = avg_score
                    self.best_model_name = name
                    
                    # Train on full dataset
                    model.fit(messages, labels)
                    self.model = model
                    
                    print(f"   ✅ New best model! ({name})")
                    
                    # Save immediately
                    self.save_model()
                    
            except Exception as e:
                print(f"   ❌ Failed: {e}")
        
        # Final evaluation
        print(f"\n" + "=" * 60)
        print(f"🏆 BEST MODEL: {self.best_model_name}")
        print(f"📊 Best F1 Score: {self.best_score:.4f}")
        print(f"=" * 60)
        
        return self.model
    
    def predict(self, text):
        """
        Predict if a single message is a scam
        
        Args:
            text: SMS text to analyze
        
        Returns:
            dict with prediction results
        """
        if self.model is None:
            self.load_model()
        
        if self.model is None:
            return {"error": "Model not trained"}
        
        # Get probability
        try:
            proba = self.model.predict_proba([text])[0]
            scam_probability = proba[1] if len(proba) > 1 else proba[0]
        except:
            # Some models don't have predict_proba
            prediction = self.model.predict([text])[0]
            scam_probability = float(prediction)
        
        # Determine risk level
        if scam_probability >= 0.70:
            risk_level = "HIGH RISK"
        elif scam_probability >= 0.40:
            risk_level = "MEDIUM RISK"
        elif scam_probability >= 0.20:
            risk_level = "LOW RISK"
        else:
            risk_level = "SAFE"
        
        return {
            "is_scam": scam_probability >= 0.50,
            "scam_probability": round(scam_probability * 100, 1),
            "risk_level": risk_level,
            "model_used": self.best_model_name,
            "confidence": round(self.best_score * 100, 1)
        }
    
    def predict_batch(self, messages):
        """Predict for multiple messages"""
        if self.model is None:
            self.load_model()
        
        results = []
        try:
            probabilities = self.model.predict_proba(messages)
            for i, proba in enumerate(probabilities):
                scam_prob = proba[1] if len(proba) > 1 else proba[0]
                results.append({
                    "message": messages[i][:100],
                    "scam_probability": round(scam_prob * 100, 1),
                    "is_scam": scam_prob >= 0.5
                })
        except:
            predictions = self.model.predict(messages)
            for i, pred in enumerate(predictions):
                results.append({
                    "message": messages[i][:100],
                    "scam_probability": float(pred) * 100,
                    "is_scam": bool(pred)
                })
        
        return results
    
    def save_model(self):
        """Save model and metadata to disk"""
        os.makedirs('detector/ml/models', exist_ok=True)
        
        if self.model:
            joblib.dump(self.model, self.model_path)
            print(f"   💾 Model saved to {self.model_path}")
        
        # Save metadata
        metadata = {
            'best_score': self.best_score,
            'best_model_name': self.best_model_name
        }
        with open('detector/ml/models/metadata.pkl', 'wb') as f:
            pickle.dump(metadata, f)
    
    def load_model(self):
        """Load model from disk"""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            print(f"   📂 Model loaded from {self.model_path}")
            
            if os.path.exists('detector/ml/models/metadata.pkl'):
                with open('detector/ml/models/metadata.pkl', 'rb') as f:
                    metadata = pickle.load(f)
                    self.best_score = metadata.get('best_score', 0)
                    self.best_model_name = metadata.get('best_model_name', '')
            
            return True
        return False
    
    def evaluate(self, messages, labels):
        """Evaluate model on test data"""
        if self.model is None:
            self.load_model()
        
        if self.model is None:
            return {"error": "No model available"}
        
        predictions = self.model.predict(messages)
        
        report = classification_report(labels, predictions, target_names=['Legitimate', 'Scam'], output_dict=True)
        cm = confusion_matrix(labels, predictions)
        
        return {
            "accuracy": accuracy_score(labels, predictions),
            "f1_score": f1_score(labels, predictions),
            "classification_report": report,
            "confusion_matrix": cm.tolist()
        }


# Quick train function for Django management command
def quick_train():
    """Quick training function for management command"""
    trainer = ScamDetectionModel()
    model = trainer.train()
    trainer.save_model()
    
    # Test with example
    test_messages = [
        "URGENT: Your M-Pesa has been suspended. Send PIN to verify.",
        "Hello, can you pick up milk on your way home?",
        "Congratulations you won Ksh 500000! Send 1000 to claim.",
        "Your salary has been credited to your account.",
    ]
    
    print("\n🧪 Testing model:")
    for msg in test_messages:
        result = trainer.predict(msg)
        print(f"   {result['risk_level']:12s} | {msg[:60]}")
    
    return trainer


if __name__ == "__main__":
    quick_train()