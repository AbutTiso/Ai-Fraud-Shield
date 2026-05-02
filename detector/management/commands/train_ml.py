# detector/management/commands/train_ml.py
"""
Django management command to train ML models
Usage: python manage.py train_ml
"""

from django.core.management.base import BaseCommand
from detector.ml_trainer import run_training


class Command(BaseCommand):
    help = 'Train ML models for scam detection using existing data'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting ML training...'))
        
        try:
            trainer = run_training()
            self.stdout.write(self.style.SUCCESS('✅ Training completed successfully!'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Training failed: {e}'))