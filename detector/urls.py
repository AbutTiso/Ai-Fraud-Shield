# detector/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # =========================
    # Main Pages (Frontend)
    # =========================
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('how-it-works/', views.how_it_works, name='how_it_works'),
    path('faq/', views.faq, name='faq'),
    path('scam-alerts/', views.scam_alerts, name='scam_alerts_page'),
    path('safety-tips/', views.safety_tips, name='safety_tips'),
    path('contact/', views.contact, name='contact'),
    path('report-scam/', views.report_scam, name='report_scam'),
    path('report-phishing/', views.report_phishing, name='report_phishing'),

    # =========================
    # Core Detection APIs
    # =========================
    path('api/detect-sms/', views.detect_sms, name='detect_sms'),
    path('api/detect-email/', views.detect_email, name='detect_email'),
    path('api/detect-whatsapp/', views.detect_whatsapp, name='detect_whatsapp'),
    path('api/detect-screenshot/', views.detect_screenshot, name='detect_screenshot'),
    path('api/detect-screenshot-text/', views.detect_screenshot_text, name='detect_screenshot_text'),
    path('api/check-url/', views.check_url, name='check_url'),

    # =========================
    # Utility APIs
    # =========================
    path('api/check-phone/', views.check_phone, name='check_phone'),
    path('api/check-link/', views.check_link, name='check_link'),
    path('api/submit-feedback/', views.submit_feedback, name='submit_feedback'),

    # =========================
    # Analytics & Reporting
    # =========================
    path('api/stats/', views.get_stats, name='get_stats'),
    path('api/export/', views.export_reports, name='export_reports'),
    path('api/scam-alerts/', views.get_scam_alerts, name='scam_alerts_api'),

    # =========================
    # System Health
    # =========================
    path('api/health/', views.health_check, name='health_check'),
    
    #==========================
    # Phone calls detection
    #==========================
    # Add to urlpatterns in detector/urls.py
    path('api/detect-call/', views.detect_call, name='detect_call'),
    path('api/check-phone/', views.check_phone, name='check_phone'),
    path('api/report-scam-call/', views.report_scam_call, name='report_scam_call'),
    path('api/detect-web/', views.detect_web, name='detect_web'),
    path('api/detect-telegram/', views.detect_telegram, name='detect_telegram'),
    path('api/predict-ml/', views.predict_ml, name='predict_ml'),
    
    # Blocklist
    path('api/report-number/', views.report_number, name='report_number'),
    path('api/vote-number/', views.vote_number, name='vote_number'),
    path('api/check-blocklist/', views.check_blocklist, name='check_blocklist'),
    path('api/check-blocklist/<str:phone_number>/', views.check_blocklist, name='check_blocklist_number'),
    path('api/top-scam-numbers/', views.top_scam_numbers, name='top_scam_numbers'),
    path('api/analyze-email/', views.analyze_forwarded_email, name='analyze_forwarded_email'),
    path('api/recent-activity/', views.recent_activity, name='recent_activity'),
]