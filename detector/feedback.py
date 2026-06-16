# detector/feedback.py
"""
Feedback Collector - Saves user verdicts and triggers ML retraining
"""

import json
import os
from datetime import datetime
from django.db import models


class FeedbackCollector:
    """Collect user feedback for ML training and continuous improvement"""
    
    def __init__(self):
        self.feedback_dir = os.path.join(os.path.dirname(__file__), 'data')
        self.feedback_file = os.path.join(self.feedback_dir, 'feedback_data.json')
        self.retrain_threshold = 20  # Retrain ML after this many new feedbacks
        self._ensure_data_dir()
    
    def _ensure_data_dir(self):
        """Ensure data directory exists"""
        os.makedirs(self.feedback_dir, exist_ok=True)
    
    def save_feedback(self, detection_id, original_text, system_score, user_verdict, 
                      detection_type='SMS', user_id=None, actual_result=None):
        """
        Save user feedback for ML training
        
        Args:
            detection_id: ID of the ScamReport
            original_text: The original message text
            system_score: Score the system gave (0-100)
            user_verdict: 'scam' or 'legitimate' or 'correct' or 'incorrect'
            detection_type: SMS, EMAIL, URL, etc.
            user_id: Who provided feedback
            actual_result: Optional confirmed result
        """
        feedback = {
            'id': detection_id,
            'timestamp': datetime.now().isoformat(),
            'original_text': original_text[:500],
            'system_score': system_score,
            'user_verdict': user_verdict,
            'detection_type': detection_type,
            'user_id': str(user_id) if user_id else 'anonymous',
            'actual_result': actual_result,
            'used_for_training': False,
        }
        
        # Save to file
        try:
            existing = self._load_all()
            existing.append(feedback)
            with open(self.feedback_file, 'w') as f:
                json.dump(existing, f, indent=2)
            
            # Check if we should trigger retraining
            new_count = self._count_untrained()
            print(f"📝 Feedback saved. Untrained feedbacks: {new_count}/{self.retrain_threshold}")
            
            if new_count >= self.retrain_threshold:
                self.trigger_retraining()
            
            return True, new_count
        except Exception as e:
            print(f"Feedback save error: {e}")
            return False, 0
    
    def _load_all(self):
        """Load all feedback entries"""
        try:
            if os.path.exists(self.feedback_file):
                with open(self.feedback_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return []
    
    def _count_untrained(self):
        """Count feedback entries not yet used for training"""
        entries = self._load_all()
        return sum(1 for e in entries if not e.get('used_for_training', False))
    
    def trigger_retraining(self):
        """
        Trigger ML model retraining with new feedback data.
        Called automatically when threshold is reached.
        """
        try:
            print("\n" + "="*60)
            print("🔄 TRIGGERING ML RETRAINING FROM USER FEEDBACK")
            print("="*60)
            
            from .ml_trainer import FraudMLTrainer
            trainer = FraudMLTrainer()
            
            # Load existing training data from ScamReport
            texts, labels = trainer.load_training_data(min_samples=50)
            
            if texts is None:
                print("⚠️ Not enough data for retraining yet")
                return False
            
            # Add feedback-corrected labels
            feedbacks = self._load_all()
            untrained = [f for f in feedbacks if not f.get('used_for_training', False)]
            
            for fb in untrained:
                if fb.get('user_verdict') == 'scam' and fb.get('system_score', 0) < 40:
                    # User says it's a scam but system scored low
                    texts.append(fb['original_text'])
                    labels.append(1)  # Mark as scam
                
                elif fb.get('user_verdict') == 'legitimate' and fb.get('system_score', 0) >= 40:
                    # User says legitimate but system scored high
                    texts.append(fb['original_text'])
                    labels.append(0)  # Mark as legitimate
            
            # Retrain
            if len(texts) > 50:
                trainer.train_sms_model(texts, labels)
                trainer.save_models()
                
                # Mark feedbacks as trained
                for fb in feedbacks:
                    fb['used_for_training'] = True
                with open(self.feedback_file, 'w') as f:
                    json.dump(feedbacks, f, indent=2)
                
                print(f"✅ ML Retraining complete! Used {len(untrained)} feedback corrections")
                return True
            else:
                print("⚠️ Still not enough data after adding feedback")
                return False
                
        except Exception as e:
            print(f"❌ Retraining error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_accuracy_stats(self):
        """Calculate detection accuracy based on user feedback"""
        feedbacks = self._load_all()
        total = len(feedbacks)
        
        if total == 0:
            return {
                'accuracy': 0,
                'total': 0,
                'agreement_rate': 0,
                'message': 'No feedback collected yet'
            }
        
        # Calculate agreement rate (user agrees with system)
        agreements = 0
        for fb in feedbacks:
            system_is_scam = fb.get('system_score', 0) >= 40
            user_says_scam = fb.get('user_verdict') == 'scam'
            if system_is_scam == user_says_scam:
                agreements += 1
        
        agreement_rate = round((agreements / total) * 100, 1)
        
        return {
            'accuracy': agreement_rate,
            'total': total,
            'agreement_rate': agreement_rate,
            'untrained': self._count_untrained(),
            'threshold': self.retrain_threshold,
            'message': f'{agreement_rate}% user agreement based on {total} feedback reports'
        }
    
    def mark_for_training(self, detection_id, text, correct_label):
        """
        Directly add a training example.
        correct_label: 1 for scam, 0 for legitimate
        """
        return self.save_feedback(
            detection_id=detection_id,
            original_text=text,
            system_score=100 if correct_label == 1 else 0,
            user_verdict='scam' if correct_label == 1 else 'legitimate',
            actual_result='confirmed'
        )


# Singleton instance
feedback_collector = FeedbackCollector()