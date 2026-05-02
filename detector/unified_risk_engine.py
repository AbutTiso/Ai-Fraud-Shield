# detector/unified_risk_engine.py
"""
Unified Risk Engine - Works with your existing detectors
"""

import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

# Import your existing modules
from .sms_detector import detect_sms_scam
from .email_detector import EmailScamDetector

# Import URL analyzer with correct function name
from .url_analyzer import LEGITIMATE_DOMAINS, analyze_url_safely

# Try to import optional modules safely
try:
    from .phone_detector import check_phone_number, detect_call_scam
except ImportError:
    check_phone_number = None
    detect_call_scam = None

try:
    from .whatsapp_detector import detect_whatsapp_scam
except ImportError:
    detect_whatsapp_scam = None

# Try to import ML enhancement (optional)
try:
    from .ml_enhanced import HybridScamDetector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    HybridScamDetector = None


class UnifiedRiskEngine:
    """
    Single entry point for all fraud detection
    """
    
    def __init__(self, use_ml: bool = False):
        """
        Initialize the unified risk engine
        
        Args:
            use_ml: Whether to use ML enhancement (if available)
        """
        self.email_detector = EmailScamDetector()
        self.legitimate_domains = LEGITIMATE_DOMAINS if LEGITIMATE_DOMAINS else set()
        
        # ML enhancement (optional)
        self.use_ml = use_ml and ML_AVAILABLE
        self.ml_enhanced_sms = None
        self.ml_enhanced_email = None
        
        if self.use_ml and HybridScamDetector:
            try:
                self.ml_enhanced_sms = HybridScamDetector(detect_sms_scam)
                self.ml_enhanced_email = HybridScamDetector(self.email_detector.detect)
                print("✅ ML enhancement enabled")
            except Exception as e:
                print(f"⚠️ ML initialization failed: {e}")
                self.use_ml = False
    
    def get_dashboard_stats(self) -> Dict:
        """Get statistics for dashboard from database"""
        try:
            # Try to import models
            from .models import ScamReport, PhoneRisk, UrlRisk
            from django.utils import timezone
            
            stats = {
                'total_scams_reported': ScamReport.objects.count(),
                'high_risk_phones': PhoneRisk.objects.filter(risk_score__gte=70).count() if PhoneRisk else 0,
                'malicious_urls': UrlRisk.objects.filter(is_phishing=True).count() if UrlRisk else 0,
                'recent_reports': ScamReport.objects.filter(
                    date_reported__gte=timezone.now() - timedelta(days=7)
                ).count() if ScamReport else 0
            }
            
            return stats
        except Exception as e:
            print(f"Dashboard stats error: {e}")
            # Return default stats if database not available
            return {
                'total_scams_reported': 0,
                'high_risk_phones': 0,
                'malicious_urls': 0,
                'recent_reports': 0,
                'error': str(e)
            }
    
    def analyze_sms(self, sms_text: str) -> Dict[str, Any]:
        """Analyze SMS message"""
        # Get rule-based result
        result = detect_sms_scam(sms_text)
        score = result.get('score', 0)
        
        # Apply ML enhancement if available
        if self.use_ml and self.ml_enhanced_sms:
            try:
                ml_result = self.ml_enhanced_sms.predict(sms_text, result)
                score = ml_result.get('final_score', score)
            except Exception as e:
                print(f"ML prediction error: {e}")
        
        return {
            'detection_type': 'SMS',
            'timestamp': datetime.now().isoformat(),
            'score': score,
            'risk_level': self._get_risk_level(score),
            'warnings': result.get('warnings', []),
            'high_risk_found': result.get('high_risk_found', []),
            'medium_risk_found': result.get('medium_risk_found', []),
            'recommendations': result.get('recommendations', []),
            'explanation': self._generate_explanation(score),
            'is_ml_enhanced': self.use_ml
        }
    
    def analyze_email(self, email_content: str, sender: str = None) -> Dict[str, Any]:
        """Analyze email"""
        try:
            result = self.email_detector.detect(email_content)
        except AttributeError:
            result = {'score': 0, 'warnings': []}
        
        score = result.get('score', 0)
        
        # Apply ML enhancement if available
        if self.use_ml and self.ml_enhanced_email:
            try:
                ml_result = self.ml_enhanced_email.predict(email_content, result)
                score = ml_result.get('final_score', score)
            except Exception as e:
                print(f"ML prediction error: {e}")
        
        return {
            'detection_type': 'EMAIL',
            'timestamp': datetime.now().isoformat(),
            'score': score,
            'risk_level': self._get_risk_level(score),
            'warnings': result.get('warnings', []),
            'phishing_indicators': result.get('phishing_indicators', []),
            'explanation': self._generate_explanation(score),
            'is_ml_enhanced': self.use_ml
        }
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for phishing"""
        try:
            # Call your existing analyze_url_safely function
            result = analyze_url_safely(url)
            score = result.get('score', 0)
            
            return {
                'detection_type': 'URL',
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'score': score,
                'risk_level': self._get_risk_level(score),
                'is_phishing': score >= 50,
                'warnings': result.get('reasons', []),
                'domain': result.get('domain', 'unknown'),
                'has_https': result.get('has_https', False),
                'message': result.get('message', ''),
                'emoji': result.get('emoji', '🔗'),
                'explanation': self._generate_url_explanation(score),
                'is_ml_enhanced': False
            }
        except Exception as e:
            return self._basic_url_check(url)
    
    def analyze_phone(self, phone_number: str) -> Dict[str, Any]:
        """Analyze phone number"""
        if check_phone_number:
            try:
                result = check_phone_number(phone_number)
                score = result.get('risk_score', 0)
                return {
                    'detection_type': 'PHONE',
                    'timestamp': datetime.now().isoformat(),
                    'phone_number': phone_number,
                    'score': score,
                    'risk_level': self._get_risk_level(score),
                    'reports_count': result.get('reports_count', 0),
                    'is_known_scam': score > 50,
                    'explanation': self._generate_phone_explanation(score),
                    'is_ml_enhanced': False
                }
            except Exception as e:
                print(f"Phone detector error: {e}")
        
        return {
            'detection_type': 'PHONE',
            'timestamp': datetime.now().isoformat(),
            'phone_number': phone_number,
            'score': 0,
            'risk_level': 'LOW_RISK',
            'reports_count': 0,
            'is_known_scam': False,
            'explanation': "No scam reports for this number",
            'is_ml_enhanced': False
        }
    
    def analyze_whatsapp(self, message: str, sender: str = None) -> Dict[str, Any]:
        """Analyze WhatsApp message"""
        if detect_whatsapp_scam:
            try:
                result = detect_whatsapp_scam(message, sender)
                score = result.get('score', 0)
                return {
                    'detection_type': 'WHATSAPP',
                    'timestamp': datetime.now().isoformat(),
                    'sender': sender,
                    'score': score,
                    'risk_level': self._get_risk_level(score),
                    'warnings': result.get('warnings', []),
                    'explanation': self._generate_explanation(score),
                    'is_ml_enhanced': False
                }
            except Exception as e:
                print(f"WhatsApp detector error: {e}")
        
        return self.analyze_sms(message)
    
    def auto_detect(self, content: str) -> Dict[str, Any]:
        """Auto-detect content type and route to appropriate analyzer"""
        if content.startswith(('http://', 'https://', 'www.')):
            return self.analyze_url(content)
        
        phone_pattern = re.compile(r'^(\+254|0)[17]\d{8}$')
        if phone_pattern.match(content.replace(' ', '').replace('-', '')):
            return self.analyze_phone(content)
        
        if '@' in content and ('.com' in content or '.co.ke' in content):
            return self.analyze_email(content)
        
        if 'whatsapp' in content.lower() or 'wa.me' in content.lower():
            return self.analyze_whatsapp(content)
        
        return self.analyze_sms(content)
    
    def get_legitimate_domains(self) -> set:
        return self.legitimate_domains
    
    def _get_risk_level(self, score: int) -> str:
        if score >= 70:
            return 'HIGH_RISK'
        elif score >= 40:
            return 'MEDIUM_RISK'
        elif score >= 15:
            return 'LOW_RISK'
        else:
            return 'SAFE'
    
    def _generate_explanation(self, score: int) -> str:
        if score >= 70:
            return f"⚠️ HIGH RISK ({score:.0f}%): This message contains multiple scam indicators. Do not respond, click links, or share personal information."
        elif score >= 40:
            return f"⚠️ MEDIUM RISK ({score:.0f}%): This message shows suspicious patterns. Verify the sender before taking action."
        elif score >= 15:
            return f"🔵 LOW RISK ({score:.0f}%): Minor suspicious elements detected. Exercise normal caution."
        else:
            return f"✅ SAFE ({score:.0f}%): No scam indicators detected."
    
    def _generate_url_explanation(self, score: int) -> str:
        if score >= 70:
            return f"🔴 CRITICAL ({score:.0f}%): This URL is highly dangerous! Do NOT click or visit!"
        elif score >= 50:
            return f"🔴 HIGH RISK ({score:.0f}%): This URL appears to be a phishing scam! Do NOT click!"
        elif score >= 30:
            return f"🟡 SUSPICIOUS ({score:.0f}%): This URL has suspicious characteristics. Verify before clicking."
        elif score >= 15:
            return f"🔵 CAUTION ({score:.0f}%): Minor suspicious elements. Proceed with caution."
        else:
            return f"🟢 SAFE ({score:.0f}%): This URL appears legitimate."
    
    def _generate_phone_explanation(self, score: int) -> str:
        if score >= 70:
            return f"📞 HIGH RISK ({score:.0f}%): This number has multiple scam reports. Do not answer or call back."
        elif score >= 40:
            return f"📞 MEDIUM RISK ({score:.0f}%): This number has some scam reports. Be cautious."
        else:
            return f"📞 SAFE ({score:.0f}%): No scam reports for this number."
    
    def _basic_url_check(self, url: str) -> Dict:
        """Fallback URL check"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        is_legitimate = domain in self.legitimate_domains
        suspicious_patterns = ['secure', 'verify', 'login', 'update', 'confirm', 'account']
        has_suspicious = any(pattern in domain for pattern in suspicious_patterns)
        
        if is_legitimate:
            score = 0
            warnings = ["Domain is in trusted whitelist"]
            message = "✅ This is a verified legitimate domain"
        elif has_suspicious:
            score = 70
            warnings = ["Domain contains suspicious keywords"]
            message = "⚠️ Domain appears suspicious"
        else:
            score = 30
            warnings = ["Domain not recognized as legitimate"]
            message = "Domain not in whitelist. Verify carefully."
        
        return {
            'detection_type': 'URL',
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'score': score,
            'risk_level': self._get_risk_level(score),
            'is_phishing': score > 50,
            'warnings': warnings,
            'domain': domain,
            'has_https': parsed.scheme == 'https',
            'message': message,
            'emoji': '🔗',
            'explanation': self._generate_url_explanation(score),
            'is_ml_enhanced': False
        }

        # Add this method to UnifiedRiskEngine class

        def load_ml_models(self):
            """Load trained ML models if available"""
            try:
                from .ml_trainer import FraudMLTrainer
                self.ml_trainer = FraudMLTrainer()
                self.ml_trainer.load_models()
                self.ml_available = True
                print("✅ ML models loaded successfully")
            except Exception as e:
                print(f"⚠️ ML models not available: {e}")
                self.ml_available = False

        def predict_with_ml(self, text, detection_type='sms'):
            """Get ML prediction for text"""
            if not self.ml_available:
                return None
            
            try:
                if detection_type == 'sms':
                    return self.ml_trainer.predict_sms(text)
                elif detection_type == 'url':
                    return self.ml_trainer.predict_url(text)
            except Exception as e:
                print(f"ML prediction error: {e}")
                return None

# Create a singleton instance
risk_engine = UnifiedRiskEngine(use_ml=False)  # Set to True when ML is ready