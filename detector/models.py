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
    
    def __str__(self):
        return f"{self.report_type} - Score: {self.risk_score} - {self.date_reported.date()}"


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
    scam_patterns_detected = models.TextField(blank=True)  # JSON or comma-separated patterns
    last_message_preview = models.CharField(max_length=200, blank=True)
    first_reported = models.DateTimeField(auto_now_add=True)
    last_reported = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'WhatsApp Risk'
        verbose_name_plural = 'WhatsApp Risks'
        ordering = ['-risk_score', '-reports_count']
    
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
        
        self.save()
    
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