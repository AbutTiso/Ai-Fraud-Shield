# detector/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

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
    
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    content = models.TextField()
    risk_score = models.IntegerField()
    risk_level = models.CharField(max_length=20)
    reported_by = models.CharField(max_length=100, blank=True, null=True)
    date_reported = models.DateTimeField(auto_now_add=True)
    
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