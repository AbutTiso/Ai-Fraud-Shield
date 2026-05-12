from django.contrib import admin
from django.contrib.admin import AdminSite
from django.db.models import Count, Q
from django.utils import timezone
from .models import ScamReport, PhoneRisk, EmailRisk, UrlRisk, ScreenshotReport, WhatsAppRisk, BlockedNumber, Company, UserProfile

# Custom Admin Site
class FraudShieldAdminSite(AdminSite):
    site_header = 'AI Fraud Shield Administration'
    site_title = 'AI Fraud Shield Admin'
    index_title = 'Fraud Shield Dashboard'
    
    def each_context(self, request):
        context = super().each_context(request)
        
        today = timezone.now().date()
        week_ago = today - timezone.timedelta(days=7)
        
        reports = ScamReport.objects.all()
        
        # Weekly data for chart
        weekly_data = []
        for i in range(6, -1, -1):
            day = today - timezone.timedelta(days=i)
            weekly_data.append(reports.filter(date_reported__date=day).count())
        
        context.update({
            'total_scans': reports.count(),
            'high_risk': reports.filter(risk_score__gte=70).count(),
            'blocked_numbers': BlockedNumber.objects.filter(status__in=['CONFIRMED', 'BLOCKED']).count(),
            'companies': Company.objects.filter(is_active=True).count(),
            'today_scans': reports.filter(date_reported__date=today).count(),
            'today_scams': reports.filter(date_reported__date=today, risk_score__gte=50).count(),
            'weekly_data': ','.join(map(str, weekly_data)),
            'sms_count': reports.filter(report_type='SMS').count(),
            'email_count': reports.filter(report_type='EMAIL').count(),
            'call_count': reports.filter(report_type='CALL').count(),
            'whatsapp_count': reports.filter(report_type='WHATSAPP').count(),
            'url_count': reports.filter(report_type='URL').count(),
            'recent_reports': reports.order_by('-date_reported')[:20],
        })
        
        return context


# Register models
@admin.register(ScamReport)
class ScamReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_type', 'risk_score', 'risk_level', 'user', 'company', 'date_reported')
    list_filter = ('report_type', 'risk_level', 'date_reported')
    search_fields = ('content',)
    date_hierarchy = 'date_reported'
    ordering = ('-date_reported',)


@admin.register(BlockedNumber)
class BlockedNumberAdmin(admin.ModelAdmin):
    list_display = ('phone_number', 'report_count', 'confidence_score', 'status', 'scam_category', 'first_reported')
    list_filter = ('status', 'scam_category')
    search_fields = ('phone_number', 'description')
    ordering = ('-confidence_score',)


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'phone', 'is_active', 'total_staff', 'total_scans', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('name', 'email')
    
    def total_staff(self, obj):
        return obj.userprofile_set.count()
    total_staff.short_description = 'Staff Count'
    
    def total_scans(self, obj):
        return ScamReport.objects.filter(company=obj).count()
    total_scans.short_description = 'Total Scans'


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'company', 'role', 'department', 'is_active', 'created_at')
    list_filter = ('role', 'company', 'is_active')
    search_fields = ('user__username', 'company__name')