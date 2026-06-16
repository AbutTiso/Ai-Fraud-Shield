# detector/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Company(models.Model):
    """Organization or Firm using the platform"""
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    email = models.EmailField()
    phone = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)
    logo = models.CharField(max_length=500, blank=True, help_text="URL to company logo")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_companies')
    
    class Meta:
        verbose_name_plural = 'Companies'
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def total_scans(self):
        return ScamReport.objects.filter(user__userprofile__company=self).count()
    
    def total_staff(self):
        return self.userprofile_set.count()
    
    
class ScamReport(models.Model):
    """Store all scam reports from users"""
    REPORT_TYPES = [
        ('SMS', 'SMS Message'),
        ('EMAIL', 'Email'),
        ('URL', 'Website Link'),
        ('PHONE', 'Phone Number'),
        ('WHATSAPP', 'WhatsApp Chat'),
        ('SCREENSHOT', 'Screenshot'),
        ('CALL', 'Phone Call'),
        ('TELEGRAM', 'Telegram Message'),
        ('USSD', 'USSD Report'),
        ('WEB', 'Web Page'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='scam_reports')
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True, blank=True, related_name='company_reports')
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    content = models.TextField()
    risk_score = models.IntegerField()
    risk_level = models.CharField(max_length=20)
    reported_by = models.CharField(max_length=100, blank=True, null=True)
    date_reported = models.DateTimeField(auto_now_add=True)
    county = models.CharField(max_length=100, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    
    class Meta:
        ordering = ['-date_reported']
        verbose_name = 'Scam Report'
        verbose_name_plural = 'Scam Reports'
        indexes = [
            models.Index(fields=['risk_score'], name='idx_scam_score'),
            models.Index(fields=['report_type'], name='idx_scam_type'),
            models.Index(fields=['date_reported'], name='idx_scam_date'),
            models.Index(fields=['user'], name='idx_scam_user'),
            models.Index(fields=['company'], name='idx_scam_company'),
        ]
    
    def __str__(self):
        return f"{self.report_type} - Score: {self.risk_score} - {self.date_reported.date()}"
    
    @property
    def is_high_risk(self):
        return self.risk_score >= 70
    
    @property
    def is_scam(self):
        return self.risk_score >= 40


class PhoneRisk(models.Model):
    """Track phone numbers reported as scam"""
    phone_number = models.CharField(max_length=15, unique=True)
    risk_score = models.IntegerField(default=0)
    reports_count = models.IntegerField(default=0)
    last_reported = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Phone Risk'
        verbose_name_plural = 'Phone Risks'
        ordering = ['-risk_score', '-reports_count']
        indexes = [
            models.Index(fields=['phone_number'], name='idx_phone_num'),
            models.Index(fields=['risk_score'], name='idx_phone_risk'),
        ]
    
    def __str__(self):
        return f"{self.phone_number} - Risk: {self.risk_score}% - Reports: {self.reports_count}"


class EmailRisk(models.Model):
    """Track email addresses reported as scam"""
    email_address = models.EmailField(unique=True)
    risk_score = models.IntegerField(default=0)
    reports_count = models.IntegerField(default=0)
    last_reported = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Email Risk'
        verbose_name_plural = 'Email Risks'
        ordering = ['-risk_score', '-reports_count']
        indexes = [
            models.Index(fields=['email_address'], name='idx_email_addr'),
        ]
    
    def __str__(self):
        return f"{self.email_address} - Risk: {self.risk_score}% - Reports: {self.reports_count}"


class UrlRisk(models.Model):
    """Track malicious URLs"""
    url = models.URLField(unique=True)
    domain = models.CharField(max_length=255)
    risk_score = models.IntegerField(default=0)
    reports_count = models.IntegerField(default=0)
    is_phishing = models.BooleanField(default=False)
    date_added = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'URL Risk'
        verbose_name_plural = 'URL Risks'
        ordering = ['-risk_score', '-date_added']
        indexes = [
            models.Index(fields=['domain'], name='idx_url_domain'),
            models.Index(fields=['is_phishing'], name='idx_url_phish'),
        ]
    
    def __str__(self):
        return f"{self.domain} - Phishing: {self.is_phishing} - Risk: {self.risk_score}%"


class ScreenshotReport(models.Model):
    """Store screenshot scam reports"""
    image_path = models.CharField(max_length=500)
    extracted_text = models.TextField()
    risk_score = models.IntegerField()
    risk_level = models.CharField(max_length=20)
    has_fake_mpesa = models.BooleanField(default=False)
    detected_amount = models.CharField(max_length=50, blank=True)
    detected_number = models.CharField(max_length=50, blank=True)
    date_reported = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Screenshot Report'
        verbose_name_plural = 'Screenshot Reports'
        ordering = ['-date_reported']
    
    def __str__(self):
        return f"Screenshot - Score: {self.risk_score} - {self.date_reported.date()}"


class WhatsAppRisk(models.Model):
    """Track WhatsApp scam patterns and senders"""
    phone_number = models.CharField(max_length=15, db_index=True)
    risk_score = models.IntegerField(default=0)
    reports_count = models.IntegerField(default=0)
    scam_patterns_detected = models.TextField(blank=True)
    last_message_preview = models.CharField(max_length=200, blank=True)
    first_reported = models.DateTimeField(auto_now_add=True)
    last_reported = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'WhatsApp Risk'
        verbose_name_plural = 'WhatsApp Risks'
        ordering = ['-risk_score', '-reports_count']
        indexes = [
            models.Index(fields=['phone_number'], name='idx_wa_phone'),
        ]
    
    def __str__(self):
        return f"WhatsApp: {self.phone_number} - Risk: {self.risk_score}% - Reports: {self.reports_count}"
    
    
class BlockedNumber(models.Model):
    """Crowdsourced scam number blocklist"""
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending Review'),
        ('CONFIRMED', 'Confirmed Scam'),
        ('REJECTED', 'Not a Scam'),
        ('BLOCKED', 'Auto-Blocked'),
    ]
    
    id = models.AutoField(primary_key=True)
    phone_number = models.CharField(max_length=15, unique=True, db_index=True)
    report_count = models.IntegerField(default=1)
    upvotes = models.IntegerField(default=0)
    downvotes = models.IntegerField(default=0)
    confidence_score = models.FloatField(default=0.0)
    first_reported = models.DateTimeField(auto_now_add=True)
    last_reported = models.DateTimeField(auto_now=True)
    reported_by = models.CharField(max_length=500, blank=True, help_text="IPs or user IDs")
    scam_category = models.CharField(max_length=50, blank=True, help_text="e.g., M-Pesa, Bank, Insurance")
    description = models.TextField(blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    auto_blocked = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-report_count', '-confidence_score']
        indexes = [
            models.Index(fields=['phone_number'], name='idx_block_phone'),
            models.Index(fields=['status'], name='idx_block_status'),
            models.Index(fields=['confidence_score'], name='idx_block_conf'),
        ]
    
    def __str__(self):
        return f"{self.phone_number} - {self.status} ({self.report_count} reports)"
    
    def calculate_confidence(self):
        """Calculate confidence score based on reports and votes"""
        base_score = min(100, self.report_count * 15)
        vote_score = (self.upvotes - self.downvotes) * 5
        self.confidence_score = max(0, min(100, base_score + vote_score))
        
        # Auto-block if confidence is high
        if self.confidence_score >= 70 and self.report_count >= 5:
            self.status = 'BLOCKED'
            self.auto_blocked = True

    def save(self, *args, **kwargs):
        if not self.confidence_score:
            self.calculate_confidence()
        super().save(*args, **kwargs)


class UserProfile(models.Model):
    """Extends Django User with role and company"""
    ROLE_CHOICES = [
        ('SUPER_ADMIN', 'Super Admin'),
        ('COMPANY_ADMIN', 'Company Admin'),
        ('STAFF', 'Staff'),
        ('INDIVIDUAL', 'Individual User'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True, blank=True, related_name='userprofile_set')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='INDIVIDUAL')
    phone = models.CharField(max_length=15, blank=True)
    department = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
     # New subscription fields
    alert_subscription = models.BooleanField(default=False)
    alert_frequency = models.CharField(max_length=10, choices=[
        ('DAILY', 'Daily'),
        ('WEEKLY', 'Weekly'),
        ('INSTANT', 'Instant'),
    ], default='DAILY')
    alert_email = models.EmailField(null=True, blank=True)
    alert_phone = models.CharField(max_length=20, null=True, blank=True)
    
    # Takedown preferences
    takedown_notifications = models.BooleanField(default=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['role'], name='idx_profile_role'),
            models.Index(fields=['company'], name='idx_profile_company'),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.company.name if self.company else 'Individual'} ({self.role})"
    
    def is_company_admin(self):
        return self.role in ['SUPER_ADMIN', 'COMPANY_ADMIN']
    
    def can_view_all_company(self):
        return self.role in ['SUPER_ADMIN', 'COMPANY_ADMIN']
    
class UserPoints(models.Model):
    """Track user points and achievements"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='points')
    total_points = models.IntegerField(default=0)
    reports_submitted = models.IntegerField(default=0)
    scams_verified = models.IntegerField(default=0)
    numbers_blocked = models.IntegerField(default=0)
    current_streak = models.IntegerField(default=0)
    longest_streak = models.IntegerField(default=0)
    last_activity = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.total_points} pts"
    
    def add_points(self, points, action_type):
        """Add points for an action"""
        self.total_points += points
        if action_type == 'report':
            self.reports_submitted += 1
        elif action_type == 'verify':
            self.scams_verified += 1
        elif action_type == 'block':
            self.numbers_blocked += 1
        self.save()
    
    def get_level(self):
        """Get user level based on points"""
        if self.total_points >= 5000: return "🛡️ Grandmaster"
        if self.total_points >= 2000: return "🔰 Expert"
        if self.total_points >= 1000: return "⭐ Advanced"
        if self.total_points >= 500: return "🔍 Scout"
        if self.total_points >= 200: return "👶 Beginner"
        return "🌱 Newcomer"


class Badge(models.Model):
    """Achievement badges"""
    name = models.CharField(max_length=100)
    description = models.TextField()
    icon = models.CharField(max_length=10)
    points_required = models.IntegerField(default=0)
    badge_type = models.CharField(max_length=50)
    
    def __str__(self):
        return f"{self.icon} {self.name}"


class UserBadge(models.Model):
    """Badges earned by users"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='badges')
    badge = models.ForeignKey(Badge, on_delete=models.CASCADE)
    earned_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'badge']
        
class TakedownReport(models.Model):
    """Track scam takedown requests"""
    STATUS_CHOICES = [
        ('PENDING', 'Pending Review'),
        ('SUBMITTED', 'Submitted'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Takedown Successful'),
        ('FAILED', 'Takedown Failed'),
        ('REJECTED', 'Rejected by Provider'),
    ]
    
    url = models.URLField()
    domain = models.CharField(max_length=255)
    hosting_provider = models.CharField(max_length=255, blank=True)
    scam_type = models.CharField(max_length=100, blank=True)
    reported_by = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    google_reported = models.BooleanField(default=False)
    hosting_reported = models.BooleanField(default=False)
    brand_notified = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status'], name='idx_takedown_status'),
            models.Index(fields=['domain'], name='idx_takedown_domain'),
        ]
    
    def __str__(self):
        return f"{self.domain} - {self.status}"


class TakedownProvider(models.Model):
    """Hosting provider abuse contacts"""
    name = models.CharField(max_length=200)
    abuse_email = models.EmailField()
    abuse_url = models.URLField(blank=True)
    success_rate = models.FloatField(default=0.0)
    avg_response_time = models.CharField(max_length=50, blank=True)
    
    def __str__(self):
        return f"{self.name} ({self.success_rate}% success)"


class ImpersonatedBrand(models.Model):
    """Brands that scammers commonly impersonate"""
    name = models.CharField(max_length=200)
    official_domain = models.CharField(max_length=255)
    notification_email = models.EmailField()
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.name
    
    
class CorporateAccount(models.Model):
    """Enterprise/corporate client account"""
    PLAN_CHOICES = [
        ('FREE', 'Free Trial'),
        ('BASIC', 'Basic - Ksh 5,000/mo'),
        ('PRO', 'Professional - Ksh 15,000/mo'),
        ('ENTERPRISE', 'Enterprise - Custom'),
    ]
    
    company = models.OneToOneField(Company, on_delete=models.CASCADE)
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default='FREE')
    max_employees = models.IntegerField(default=10)
    bulk_verifications = models.IntegerField(default=0)
    bulk_verification_limit = models.IntegerField(default=100)
    api_key = models.CharField(max_length=100, unique=True, blank=True)
    widget_enabled = models.BooleanField(default=False)
    phishing_simulations = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    trial_ends = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['api_key'], name='idx_corp_apikey'),
        ]
    
    def __str__(self):
        return f"{self.company.name} - {self.plan}"
    
    def generate_api_key(self):
        import uuid
        self.api_key = f'afs_{uuid.uuid4().hex[:24]}'
        self.save()


class BulkVerification(models.Model):
    """Bulk phone number verification jobs"""
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    
    corporate = models.ForeignKey(CorporateAccount, on_delete=models.CASCADE)
    total_numbers = models.IntegerField(default=0)
    processed = models.IntegerField(default=0)
    scam_found = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    result_file = models.FileField(upload_to='bulk_results/', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"Bulk Verify #{self.id} - {self.total_numbers} numbers"


class PhishingSimulation(models.Model):
    """Phishing simulation campaigns for employee training"""
    corporate = models.ForeignKey(CorporateAccount, on_delete=models.CASCADE)
    template_name = models.CharField(max_length=200)
    target_employees = models.IntegerField(default=0)
    clicked_count = models.IntegerField(default=0)
    reported_count = models.IntegerField(default=0)
    ignored_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    @property
    def click_rate(self):
        if self.target_employees == 0: return 0
        return round((self.clicked_count / self.target_employees) * 100, 1)
    
    @property
    def report_rate(self):
        if self.target_employees == 0: return 0
        return round((self.reported_count / self.target_employees) * 100, 1)