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

# ============================================================
# WHITELIST - Same as in training
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

LEGITIMATE_PATTERNS = [
    r'(?:your|your\s+)(?:salary|loan\s+payment|bill|statement|receipt)\s+(?:of\s+)?(?:ksh|kes)\s*\d+',
    r'(?:church|mosque|temple)\s+(?:service|prayer|meeting|harambee)',
    r'(?:parent|teacher|school)\s+(?:meeting|report|fees)',
    r'(?:doctor|dentist|clinic)\s+(?:appointment|reminder)',
    r'(?:flight|train|bus)\s+(?:booking|ticket|reservation)',
    r'(?:uber|bolt|taxi)\s+(?:arriving|driver|confirmed)',
    r'(?:jumia|kilimall|carrefour|naivas)\s+(?:order|delivery|package)',
]

# ============================================================
# CONFIDENCE THRESHOLDS
# ============================================================
HIGH_CONFIDENCE_THRESHOLD = 80  # Definitely scam
SCAM_THRESHOLD = 60             # Likely scam
LOW_CONFIDENCE_THRESHOLD = 40   # Uncertain zone
SAFE_THRESHOLD = 20             # Likely safe

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
    
    # Check for official bank/corporate format without scam indicators
    if re.search(r'(?:kcb|equity|coop|absa|stanbic|ncba|standard\s+chartered)\s*:', text_lower):
        if not re.search(r'(?:urgent|verify|click|link|send\s+(?:money|pin|otp|mpin))', text_lower):
            return True
    
    return False

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
            except Exception as e:
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
    """Predict if text is a scam using ML model with confidence thresholds"""
    model = get_model()
    if model is None:
        return None
    
    cleaned = clean_text(text)
    
    # ============================================================
    # CHECK WHITELIST FIRST - Known legitimate patterns
    # ============================================================
    if is_known_legitimate(text):
        meta = get_metadata()
        return {
            'ml_score': max(0, 15),  # Force low score for known legit
            'ml_risk_level': 'SAFE',
            'ml_is_scam': False,
            'ml_confidence': 99.0,
            'model_name': meta.get('model_name', 'LogisticRegression'),
            'model_version': '1.0',
            'whitelist_match': True,
        }
    
    # Get ML prediction
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
    
    # ============================================================
    # APPLY CONFIDENCE THRESHOLDS
    # ============================================================
    if ml_score >= HIGH_CONFIDENCE_THRESHOLD:
        risk_level = "HIGH RISK"
        confidence = "HIGH"
    elif ml_score >= SCAM_THRESHOLD:
        risk_level = "MEDIUM RISK"
        confidence = "MEDIUM"
    elif ml_score >= LOW_CONFIDENCE_THRESHOLD:
        risk_level = "LOW RISK"
        confidence = "LOW"  # Uncertain zone
    elif ml_score >= SAFE_THRESHOLD:
        risk_level = "SAFE"
        confidence = "MEDIUM"
    else:
        risk_level = "SAFE"
        confidence = "HIGH"
    
    meta = get_metadata()
    
    return {
        'ml_score': ml_score,
        'ml_risk_level': risk_level,
        'ml_is_scam': ml_score >= SCAM_THRESHOLD,  # Use higher threshold
        'ml_confidence': round(meta.get('f1_score', 0.875) * 100, 1),
        'model_name': meta.get('model_name', 'LogisticRegression'),
        'model_version': '1.0',
        'confidence_level': confidence,
        'whitelist_match': False,
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