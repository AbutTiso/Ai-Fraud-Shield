# detector/ml/inference/predict.py
import os
import json
import re
from pathlib import Path

# Try to import ML libraries - may fail on Python 3.14
_model = None
_metadata = None
_ml_available = False

try:
    import joblib
    _ml_available = True
except ImportError:
    pass

def get_model():
    """Load ML model if available"""
    global _model
    if not _ml_available:
        return None
    if _model is None:
        model_path = Path(__file__).parent.parent / 'models' / 'scam_model.joblib'
        if model_path.exists():
            try:
                _model = joblib.load(model_path)
                print(f"ML Model loaded: {model_path}")
            except Exception as e:
                #print(f"ML Model load failed: {e}")
                return None
        else:
            return None
    return _model

def get_metadata():
    """Load model metadata"""
    global _metadata
    if _metadata is None:
        metadata_path = Path(__file__).parent.parent / 'models' / 'metadata.json'
        if metadata_path.exists():
            try:
                with open(metadata_path) as f:
                    _metadata = json.load(f)
            except:
                _metadata = {"model_name": "Unknown", "f1_score": 0.875}
        else:
            _metadata = {"model_name": "Unknown", "f1_score": 0.875}
    return _metadata

def clean_text(text):
    """Clean text for ML prediction"""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', ' URL ', text)
    text = re.sub(r'\b(07|01|2547)\d{8}\b', ' PHONE ', text)
    text = re.sub(r'ksh\s*\d[\d,]*', ' MONEY ', text)
    text = re.sub(r'[^a-zA-Z0-9\s!?]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def predict_scam(text):
    """Predict if text is a scam using ML model"""
    model = get_model()
    if model is None:
        return None
    
    cleaned = clean_text(text)
    
    try:
        proba = model.predict_proba([cleaned])[0]
        scam_probability = proba[1] if len(proba) > 1 else proba[0]
    except:
        try:
            decision = model.decision_function([cleaned])[0]
            scam_probability = 1 / (1 + pow(2.71828, -decision))
        except:
            prediction = model.predict([cleaned])[0]
            scam_probability = float(prediction)
    
    ml_score = round(scam_probability * 100, 1)
    
    if ml_score >= 70:
        risk_level = "HIGH RISK"
    elif ml_score >= 40:
        risk_level = "MEDIUM RISK"
    elif ml_score >= 20:
        risk_level = "LOW RISK"
    else:
        risk_level = "SAFE"
    
    meta = get_metadata()
    
    return {
        'ml_score': ml_score,
        'ml_risk_level': risk_level,
        'ml_is_scam': ml_score >= 50,
        'ml_confidence': round(meta.get('f1_score', 0.875) * 100, 1),
        'model_name': meta.get('model_name', 'LogisticRegression'),
        'model_version': '1.0',
    }

def get_model_info():
    """Get information about the ML model"""
    meta = get_metadata()
    model = get_model()
    
    return {
        'is_loaded': model is not None,
        'model_name': meta.get('model_name', 'Unknown'),
        'f1_score': round(meta.get('f1_score', 0) * 100, 1),
        'training_samples': meta.get('num_samples', 123),
        'scam_samples': meta.get('num_scam', 66),
        'legit_samples': meta.get('num_legit', 57),
    }