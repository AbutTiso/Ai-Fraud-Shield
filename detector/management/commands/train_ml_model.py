# detector/management/commands/train_ml_model.py
"""
Django management command to train ML models for scam detection
Usage: python manage.py train_ml_model
       python manage.py train_ml_model --force
       python manage.py train_ml_model --quick-test
"""

from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command
import sys
import os

# Add parent directory to path to import ml_trainer
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from detector.ml_trainer import FraudMLTrainer, run_training, quick_test


class Command(BaseCommand):
    help = 'Train ML models for scam detection using existing database reports'
    
    def add_arguments(self, parser):
        """Add command line arguments"""
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force training even with less than minimum required samples'
        )
        parser.add_argument(
            '--quick-test',
            action='store_true',
            help='Quick test of existing trained models'
        )
        parser.add_argument(
            '--min-samples',
            type=int,
            default=100,
            help='Minimum number of samples required for training (default: 100)'
        )
        parser.add_argument(
            '--save-dir',
            type=str,
            default='ml_models',
            help='Directory to save trained models (default: ml_models)'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed training output'
        )
    
    def handle(self, *args, **options):
        """Main command handler"""
        
        # Quick test mode
        if options['quick_test']:
            self.stdout.write(self.style.WARNING('\n🔍 Running quick model test...'))
            quick_test()
            return
        
        self.stdout.write(self.style.SUCCESS('\n' + '=' * 70))
        self.stdout.write(self.style.SUCCESS('🚀 AI FRAUD SHIELD - ML MODEL TRAINING'))
        self.stdout.write(self.style.SUCCESS('=' * 70))
        
        # Check if force flag is set
        force = options['force']
        min_samples = options['min_samples']
        
        self.stdout.write("\n📊 Configuration:")
        self.stdout.write(f"   Force mode: {'ON' if force else 'OFF'}")
        self.stdout.write(f"   Min samples: {min_samples}")
        self.stdout.write(f"   Save directory: {options['save_dir']}")
        self.stdout.write(f"   Verbose: {'ON' if options['verbose'] else 'OFF'}")
        
        try:
            # Import models to check data availability
            from detector.models import ScamReport
            
            report_count = ScamReport.objects.count()
            self.stdout.write("\n📈 Database status:")
            self.stdout.write(f"   Total reports: {report_count}")
            
            # Count reports with content
            content_reports = ScamReport.objects.exclude(content__isnull=True).exclude(content='')
            content_count = content_reports.count()
            self.stdout.write(f"   Reports with content: {content_count}")
            
            # Count scam vs legitimate
            scam_count = ScamReport.objects.filter(risk_score__gte=40).count()
            legit_count = ScamReport.objects.filter(risk_score__lt=40).count()
            self.stdout.write(f"   Scam reports (risk ≥ 40): {scam_count}")
            self.stdout.write(f"   Legitimate reports (risk < 40): {legit_count}")
            
            # Check if we have enough data
            if content_count < min_samples and not force:
                self.stdout.write(self.style.ERROR(
                    '\n❌ Not enough data for reliable training!'
                ))
                self.stdout.write(f"   Current: {content_count} samples")
                self.stdout.write(f"   Required: {min_samples} samples")
                self.stdout.write("\n💡 Suggestions:")
                self.stdout.write("   1. Collect more scam reports first")
                self.stdout.write("   2. Use --force flag to train anyway")
                self.stdout.write("   3. Reduce --min-samples value")
                self.stdout.write("\nExample: python manage.py train_ml_model --force")
                return
            
            if content_count < min_samples and force:
                self.stdout.write(self.style.WARNING(
                    f'\n⚠️ Training with limited data ({content_count} samples)'
                ))
                self.stdout.write("   Results may not be reliable. Proceeding anyway...")
            
            # Run training
            self.stdout.write(self.style.SUCCESS('\n' + '=' * 70))
            self.stdout.write(self.style.SUCCESS('🎯 STARTING MODEL TRAINING...'))
            self.stdout.write(self.style.SUCCESS('=' * 70))
            
            # Call the training function
            trainer = run_training()
            
            if trainer:
                # Success!
                self.stdout.write(self.style.SUCCESS('\n' + '=' * 70))
                self.stdout.write(self.style.SUCCESS('✅ TRAINING COMPLETED SUCCESSFULLY!'))
                self.stdout.write(self.style.SUCCESS('=' * 70))
                
                # Display metrics
                self.stdout.write("\n📊 Model Performance Summary:")
                
                for model_name, metrics in trainer.model_metrics.items():
                    self.stdout.write(f"\n   🔹 {model_name.upper()}:")
                    
                    if 'accuracy' in metrics:
                        self.stdout.write(f"      Accuracy: {metrics['accuracy']:.2%}")
                    if 'f1_score' in metrics:
                        self.stdout.write(f"      F1 Score: {metrics['f1_score']:.2%}")
                    if 'precision' in metrics:
                        self.stdout.write(f"      Precision: {metrics['precision']:.2%}")
                    if 'recall' in metrics:
                        self.stdout.write(f"      Recall: {metrics['recall']:.2%}")
                    if 'cv_f1_mean' in metrics:
                        self.stdout.write(f"      5-Fold CV: {metrics['cv_f1_mean']:.2%} (±{metrics['cv_f1_mean']*2:.2%})")
                    if 'training_samples' in metrics:
                        self.stdout.write(f"      Training samples: {metrics['training_samples']}")
                    if 'test_samples' in metrics:
                        self.stdout.write(f"      Test samples: {metrics['test_samples']}")
                    if 'model_name' in metrics:
                        self.stdout.write(f"      Best model: {metrics['model_name']}")
                
                # Save location
                self.stdout.write(f"\n💾 Models saved to: {options['save_dir']}/")
                
                # Next steps
                self.stdout.write(self.style.SUCCESS('\n🎯 NEXT STEPS:'))
                self.stdout.write("   1. Test models: python manage.py train_ml_model --quick-test")
                self.stdout.write("   2. Models are ready for API predictions")
                self.stdout.write("   3. Run again later with more data for better accuracy")
                
            else:
                self.stdout.write(self.style.ERROR('\n❌ Training failed!'))
                self.stdout.write("   Check that you have enough scam reports in the database.")
                
        except ImportError as e:
            self.stdout.write(self.style.ERROR(f'\n❌ Import Error: {e}'))
            self.stdout.write("   Make sure the ml_trainer.py file exists in the detector directory.")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'\n❌ Training Error: {str(e)}'))
            if options['verbose']:
                import traceback
                traceback.print_exc()
            raise CommandError(f"Training failed: {str(e)}")
    
    def get_model_summary(self, trainer):
        """Generate a summary of trained models"""
        summary = []
        
        for model_name, metrics in trainer.model_metrics.items():
            summary.append(f"\n{model_name.upper()}:")
            if 'accuracy' in metrics:
                summary.append(f"  - Accuracy: {metrics['accuracy']:.2%}")
            if 'f1_score' in metrics:
                summary.append(f"  - F1 Score: {metrics['f1_score']:.2%}")
            if 'cv_f1_mean' in metrics:
                summary.append(f"  - CV Score: {metrics['cv_f1_mean']:.2%}")
        
        return "\n".join(summary)


# Alternative: Create a simpler training command
class CommandSimple(BaseCommand):
    """
    Simplified version - just calls the main training function
    """
    help = 'Quick train ML models for scam detection'
    
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('=' * 60))
        self.stdout.write(self.style.SUCCESS('STARTING ML MODEL TRAINING'))
        self.stdout.write(self.style.SUCCESS('=' * 60))
        
        try:
            from detector.ml_trainer import run_training
            
            trainer = run_training()
            
            if trainer:
                self.stdout.write(self.style.SUCCESS('\n' + '=' * 60))
                self.stdout.write(self.style.SUCCESS('✅ TRAINING COMPLETE!'))
                self.stdout.write(self.style.SUCCESS('=' * 60))
                
                # Display best model info
                if 'ensemble' in trainer.model_metrics:
                    best = trainer.model_metrics['ensemble']
                    self.stdout.write(f"\n🎯 Best Model: {best.get('model_name', 'Ensemble')}")
                    self.stdout.write(f"   F1 Score: {best.get('f1_score', 0):.2%}")
                
            else:
                self.stdout.write(self.style.ERROR('\n❌ Training failed - insufficient data'))
                
        except ImportError as e:
            self.stdout.write(self.style.ERROR(f'\n❌ Import Error: {e}'))
            self.stdout.write("   Make sure ml_trainer.py exists in detector/")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'\n❌ Error: {e}'))