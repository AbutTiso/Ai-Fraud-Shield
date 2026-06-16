# detector/ml/inference/predict.py
"""
Enhanced ML Inference with Context Awareness
Hybrid scoring: ML + keyword + whitelist for accurate detection
"""

import os
import json
import re
import hashlib
from pathlib import Path
from datetime import datetime

# Lazy loading
_model = None
_metadata = None
_ml_available = False

try:
    import joblib
    _ml_available = True
except ImportError:
    pass

# ============================================================
# CONTEXT-AWARE WHITELIST
# ============================================================
LEGITIMATE_DOMAINS = {
    'safaricom.com', 'safaricom.co.ke', 'airtel.co.ke', 'telkom.co.ke',
    'kcbgroup.com', 'kcb.co.ke', 'equitybank.co.ke', 'coopbank.co.ke',
    'absabank.co.ke', 'stanbicbank.co.ke', 'ncbagroup.com', 'familybank.co.ke',
    'kra.go.ke', 'ecitizen.go.ke', 'nssf.go.ke', 'nhif.go.ke',
    'hudumakenya.go.ke', 'ntsa.go.ke', 'posta.co.ke', 'kenya.go.ke',
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'whatsapp.com', 'telegram.org', 'jumia.co.ke', 'kilimall.co.ke',
    'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
}

LEGITIMATE_SHORTCODES = {
    '*334#', '*544#', '*100#', '*200#', '*456#', '*131#',
    '*144#', '*282#', '*444#', '*126#', '*188#', '*234#',
}

# Context-aware legitimate patterns
# These words are fine in SOME contexts but suspicious in others
CONTEXT_SAFE_PATTERNS = {
    'bank_notification': [
        r'(?:kcb|equity|coop|absa|stanbic|ncba|family)\s*:',
        r'(?:salary|loan payment|standing order|direct debit)\s+(?:of\s+)?(?:ksh|kes)',
        r'(?:credited|debited)\s+(?:to|from)\s+(?:your\s+)?account',
        r'account\s+(?:statement|balance|activity)',
        r'(?:cheque|check)\s+(?:book|deposited|cleared)',
        r'fixed\s+deposit\s+(?:matured|renewed)',
    ],
    'mpesa_notification': [
        r'm-pesa\s*:\s*ksh\s*\d[\d,]*\s+(?:to|from)\s+\w+\s+(?:successful|completed)',
        r'm-pesa\s*:\s*you\s+(?:received|sent)\s+ksh',
        r'm-pesa\s*:\s*(?:your\s+)?balance\s+(?:is|:)',
        r'm-pesa\s*:\s*transaction\s+(?:id|cost)',
    ],
    'service_notification': [
        r'(?:your\s+)?(?:data\s+bundle|airtime|subscription)\s+(?:expir|renew)',
        r'(?:your\s+)?(?:bill|statement|invoice)\s+(?:is\s+ready|available|due)',
        r'(?:appointment|booking|reservation)\s+(?:confirmed|reminder|scheduled)',
        r'(?:your\s+)?(?:order|package|delivery)\s+(?:confirmed|dispatched|arriving)',
        r'(?:flight|train|bus)\s+(?:booking|ticket|departure)',
    ],
    'personal_communication': [
        r'^(?:hi|hello|hey|habari|niaje|vipi)\b',
        r'\b(?:please|pls|kindly)\b.*\b(?:send|share|tell|bring|pick|buy|call)\b',
        r'\b(?:meeting|dinner|lunch|party|wedding|church|prayer|service)\b',
        r'\b(?:happy\s+birthday|congratulations|pole|get\s+well)\b',
        r'\b(?:home|house|school|office|work)\b.*\b(?:today|tomorrow|monday|tuesday)\b',
    ],
}

# Words that are suspicious ONLY in certain contexts
CONTEXT_SUSPICIOUS = {
    'unsolicited_urgent': [
        r'(?<!bank\s)(?<!kcb\s)(?<!equity\s)urgent',
        r'(?<!your\s)(?<!account\s)suspended',
        r'(?<!mpesa\s)blocked.*(?:account|card)',
    ],
    'credential_request': [
        r'(?:send|share|provide|confirm|verify)\s+(?:your\s+)?(?:pin|otp|mpin|password|secret)',
        r'(?:we\s+need|please\s+send|kindly\s+share)\s+(?:your\s+)?(?:pin|otp|password)',
    ],
    'urgency_pressure': [
        r'(?:within|in\s+the\s+next)\s+\d+\s+(?:hours|minutes|days)',
        r'(?:immediately|right\s+now|asap|without\s+delay)',
        r'(?:last\s+warning|final\s+notice|last\s+chance)',
    ],
}

# ============================================================
# CONFIDENCE THRESHOLDS
# ============================================================
HIGH_CONFIDENCE_SCAM = 80
LIKELY_SCAM = 60
UNCERTAIN = 40
LIKELY_SAFE = 20


def get_model():
    """Load ML model lazily"""
    global _model
    if not _ml_available:
        return None
    if _model is None:
        model_path = Path(__file__).parent.parent / 'models' / 'scam_model.joblib'
        if model_path.exists():
            try:
                _model = joblib.load(model_path)
            except Exception:
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


def get_context_markers(text):
    """
    Analyze text for context markers.
    Returns dict of detected contexts for smarter scoring.
    """
    text_lower = text.lower()
    markers = {
        'is_bank_notification': False,
        'is_mpesa_notification': False,
        'is_service_notification': False,
        'is_personal': False,
        'has_url': False,
        'has_phone': False,
        'has_urgency': False,
        'has_credential_request': False,
        'has_money_amount': False,
        'has_prize_language': False,
        'has_swahili_scam_terms': False,
    }
    
    # Check safe contexts
    for patterns in CONTEXT_SAFE_PATTERNS.values():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                if 'salary' in pattern or 'credited' in pattern or 'debited' in pattern:
                    markers['is_bank_notification'] = True
                elif 'm-pesa' in pattern or 'mpesa' in pattern:
                    markers['is_mpesa_notification'] = True
                elif 'data bundle' in pattern or 'bill' in pattern or 'appointment' in pattern:
                    markers['is_service_notification'] = True
                elif pattern.startswith(r'^(?:hi|hello|hey'):
                    markers['is_personal'] = True
    
    # Check suspicious patterns
    for patterns in CONTEXT_SUSPICIOUS.values():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                if 'urgent' in pattern or 'suspended' in pattern:
                    markers['has_urgency'] = True
                elif 'pin' in pattern or 'otp' in pattern or 'password' in pattern:
                    markers['has_credential_request'] = True
    
    # URL presence
    if re.search(r'https?://|www\.|bit\.ly|tinyurl|short\.link', text_lower):
        markers['has_url'] = True
    
    # Phone presence
    if re.search(r'\b(07|01|2547)\d{8}\b', text_lower):
        markers['has_phone'] = True
    
    # Money amounts
    if re.search(r'\b(ksh|kes)\s*\d[\d,]*', text_lower):
        markers['has_money_amount'] = True
    
    # Prize language
    if re.search(r'won|winner|congratulations|prize|lotto|jackpot|giveaway', text_lower):
        markers['has_prize_language'] = True
    
    # Swahili scam terms
    swahili_scam = ['tuma pesa', 'namba ya siri', 'umeshinda', 'akaunti imefungwa',
                    'thibitisha', 'mpin', 'siri yako', 'fungua akaunti']
    for term in swahili_scam:
        if term in text_lower:
            markers['has_swahili_scam_terms'] = True
            break
    
    return markers


def predict_scam(text):
    """
    Enhanced hybrid prediction with context awareness.
    Combines ML score with context analysis for accurate detection.
    """
    if not text or not text.strip():
        return None
    
    meta = get_metadata()
    model = get_model()
    
    # Get context markers
    markers = get_context_markers(text)
    
    # ============================================================
    # WHITELIST CHECK: Known legitimate patterns
    # ============================================================
    if markers['is_bank_notification'] and not markers['has_credential_request'] and not markers['has_urgency']:
        return {
            'ml_score': max(0, 10),
            'ml_risk_level': 'SAFE',
            'ml_is_scam': False,
            'ml_confidence': 99.0,
            'model_name': meta.get('model_name', 'ContextAware'),
            'context': 'bank_notification',
            'whitelist_match': True,
        }
    
    if markers['is_mpesa_notification'] and not markers['has_credential_request'] and not markers['has_urgency']:
        return {
            'ml_score': max(0, 8),
            'ml_risk_level': 'SAFE',
            'ml_is_scam': False,
            'ml_confidence': 99.0,
            'model_name': meta.get('model_name', 'ContextAware'),
            'context': 'mpesa_notification',
            'whitelist_match': True,
        }
    
    if markers['is_personal'] and not markers['has_url'] and not markers['has_credential_request']:
        return {
            'ml_score': max(0, 5),
            'ml_risk_level': 'SAFE',
            'ml_is_scam': False,
            'ml_confidence': 98.0,
            'model_name': meta.get('model_name', 'ContextAware'),
            'context': 'personal_communication',
            'whitelist_match': True,
        }
    
    # ============================================================
    # BLACKLIST CHECK: Clear scam indicators
    # ============================================================
    if markers['has_credential_request'] and markers['has_urgency']:
        return {
            'ml_score': 95,
            'ml_risk_level': 'HIGH RISK',
            'ml_is_scam': True,
            'ml_confidence': 99.0,
            'model_name': meta.get('model_name', 'ContextAware'),
            'context': 'credential_request_with_urgency',
            'whitelist_match': False,
        }
    
    if markers['has_swahili_scam_terms'] and (markers['has_credential_request'] or markers['has_money_amount']):
        return {
            'ml_score': 90,
            'ml_risk_level': 'HIGH RISK',
            'ml_is_scam': True,
            'ml_confidence': 98.0,
            'model_name': meta.get('model_name', 'ContextAware'),
            'context': 'swahili_scam',
            'whitelist_match': False,
        }
    
    # ============================================================
    # ML PREDICTION
    # ============================================================
    if model is not None:
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
    else:
        # Fallback: estimate from markers
        ml_score = 0
        if markers['has_credential_request']: ml_score += 40
        if markers['has_urgency']: ml_score += 20
        if markers['has_url']: ml_score += 15
        if markers['has_phone']: ml_score += 10
        if markers['has_prize_language']: ml_score += 25
        if markers['has_money_amount']: ml_score += 10
        ml_score = min(100, ml_score)
    
    # ============================================================
    # CONTEXT ADJUSTMENT
    # ============================================================
    # Reduce score for legitimate-looking contexts
    if markers['is_service_notification'] and not markers['has_credential_request']:
        ml_score = max(0, ml_score - 20)
    
    if markers['is_bank_notification'] and not markers['has_urgency']:
        ml_score = max(0, ml_score - 15)
    
    # Increase score for dangerous combinations
    if markers['has_url'] and markers['has_urgency'] and markers['has_credential_request']:
        ml_score = min(100, ml_score + 15)
    
    if markers['has_phone'] and markers['has_credential_request']:
        ml_score = min(100, ml_score + 10)
    
    # ============================================================
    # DETERMINE RISK LEVEL
    # ============================================================
    if ml_score >= HIGH_CONFIDENCE_SCAM:
        risk_level = "HIGH RISK"
        is_scam = True
        confidence = "HIGH"
    elif ml_score >= LIKELY_SCAM:
        risk_level = "MEDIUM RISK"
        is_scam = True
        confidence = "MEDIUM"
    elif ml_score >= UNCERTAIN:
        risk_level = "LOW RISK"
        is_scam = False
        confidence = "LOW"
    elif ml_score >= LIKELY_SAFE:
        risk_level = "SAFE"
        is_scam = False
        confidence = "MEDIUM"
    else:
        risk_level = "SAFE"
        is_scam = False
        confidence = "HIGH"
    
    return {
        'ml_score': ml_score,
        'ml_risk_level': risk_level,
        'ml_is_scam': is_scam,
        'ml_confidence': round(meta.get('f1_score', 0.875) * 100, 1),
        'model_name': meta.get('model_name', 'ContextAware'),
        'confidence_level': confidence,
        'context_markers': markers,
        'whitelist_match': False,
    }


def get_model_info():
    """Get model information"""
    meta = get_metadata()
    model = get_model()
    
    return {
        'is_loaded': model is not None,
        'model_name': meta.get('model_name', 'Unknown'),
        'f1_score': round(meta.get('f1_score', 0) * 100, 1),
        'training_runs': meta.get('training_runs', 0),
        'last_trained': meta.get('last_trained', 'Unknown'),
    }


def predict_hybrid(text, keyword_score):
    """
    Hybrid prediction combining ML and keyword-based scores.
    Called from views.py detect_sms endpoint.
    """
    ml_result = predict_scam(text)
    
    if ml_result is None:
        return {'ml_score': keyword_score, 'hybrid_score': keyword_score}
    
    ml_score = ml_result.get('ml_score', 0)
    
    # Weighted combination: 60% ML, 40% keyword
    hybrid_score = round((ml_score * 0.6) + (keyword_score * 0.4), 1)
    
    # If ML is highly confident, trust it more
    if ml_result.get('confidence_level') == 'HIGH':
        hybrid_score = round((ml_score * 0.8) + (keyword_score * 0.2), 1)
    
    return {
        'ml_score': ml_score,
        'hybrid_score': hybrid_score,
        'ml_risk_level': ml_result.get('ml_risk_level'),
        'ml_is_scam': ml_result.get('ml_is_scam'),
        'ml_confidence': ml_result.get('ml_confidence'),
        'model_name': ml_result.get('model_name'),
        'context_markers': ml_result.get('context_markers', {}),
    }