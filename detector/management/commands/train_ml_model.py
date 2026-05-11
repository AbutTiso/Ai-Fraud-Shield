# detector/management/commands/train_ml_model.py
from django.core.management.base import BaseCommand
from detector.ml.training.train_model import quick_train

class Command(BaseCommand):
    help = 'Train the ML scam detection model'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('=' * 60))
        self.stdout.write(self.style.SUCCESS('STARTING ML MODEL TRAINING'))
        self.stdout.write(self.style.SUCCESS('=' * 60))
        
        trainer = quick_train()
        
        self.stdout.write(self.style.SUCCESS('\n' + '=' * 60))
        self.stdout.write(self.style.SUCCESS(
            'TRAINING COMPLETE!'
        ))
        self.stdout.write(self.style.SUCCESS(
            f'   Best Model: {trainer.best_model_name}'
        ))
        self.stdout.write(self.style.SUCCESS(
            f'   F1 Score: {trainer.best_score:.4f} ({trainer.best_score*100:.1f}%)'
        ))
        self.stdout.write(self.style.SUCCESS('=' * 60))