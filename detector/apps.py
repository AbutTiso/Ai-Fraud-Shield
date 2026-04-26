# detector/apps.py
from django.apps import AppConfig

class DetectorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'detector'
    verbose_name = 'Scam Detection System'
    
    def ready(self):
        # Import signals only if they exist
        try:
            import detector.signals
        except ImportError:
            pass