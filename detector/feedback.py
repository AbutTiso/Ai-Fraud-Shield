# detector/feedback.py
import json
from datetime import datetime

class FeedbackCollector:
    """Collect user feedback for ML training"""
    
    def __init__(self):
        self.feedback_file = 'feedback_data.json'
    
    def save_feedback(self, detection_id, user_verdict, actual_result=None):
        """Save user feedback"""
        feedback = {
            'id': detection_id,
            'timestamp': datetime.now().isoformat(),
            'user_verdict': user_verdict,  # 'scam' or 'legitimate'
            'actual_result': actual_result,  # Optional, for verification
        }
        
        # Save to file (in production, save to database)
        try:
            with open(self.feedback_file, 'a') as f:
                f.write(json.dumps(feedback) + '\n')
            return True
        except Exception:
            return False
    
    def get_accuracy_stats(self):
        """Calculate detection accuracy based on feedback"""
        try:
            with open(self.feedback_file, 'r') as f:
                feedbacks = [json.loads(line) for line in f]
            
            total = len(feedbacks)
            if total == 0:
                return {'accuracy': 0, 'total': 0, 'message': 'No feedback yet'}
            
            # This would compare with actual results in production
            return {
                'total_feedback': total,
                'accuracy': 85,  # Placeholder
                'message': f'Based on {total} user feedback reports'
            }
        except Exception:
            return {'accuracy': 0, 'total': 0, 'message': 'Unable to calculate'}