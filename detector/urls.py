# detector/urls.py
from django.urls import path
from . import views, sms_gateway
from .api import views as api_views
from .ussd import handler as ussd_handler
from . import enhancements_views

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
    path('api/detect-call/', views.detect_call, name='detect_call'),
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
    
    # SMS Gateway
    path('webhook/sms/', sms_gateway.sms_webhook, name='sms_webhook'),
    path('api/send-sms/', sms_gateway.send_sms_alert, name='send_sms_alert'),
    
    #==========================
    # Api urls
    #==========================
    path('api/v1/', api_views.api_docs, name='api_docs'),
    path('api/v1/check/sms', api_views.check_sms, name='api_check_sms'),
    path('api/v1/check/phone', api_views.check_phone, name='api_check_phone'),
    path('api/v1/check/url', api_views.check_url, name='api_check_url'),
    path('api/v1/stats', api_views.api_stats, name='api_stats'),
    path('api/v1/report', api_views.api_report, name='api_report'),
    path('api/v1/blocklist', api_views.api_blocklist, name='api_blocklist'),
    
    # Multi-Tenant Company Management
    path('api/user-stats/', views.get_user_stats, name='user_stats'),
    path('api/create-company/', views.create_company, name='create_company'),
    path('api/add-staff/', views.add_staff_to_company, name='add_staff'),
    path('api/my-company/', views.my_company, name='my_company'),
    
    # Registration
    path('register/', views.register_user, name='register'),
    path('api/register/', views.register_user, name='api_register'),
    path('api/company/<slug:slug>/', views.get_company_info, name='company_info'),
    
    # Heatmap
    path('heatmap/', views.scam_heatmap, name='scam_heatmap'),
    
    # Rewards & Leaderboard
    path('api/my-points/', views.my_points, name='my_points'),
    path('api/leaderboard/', views.leaderboard, name='api_leaderboard'),
    path('leaderboard/', views.leaderboard_page, name='leaderboard_page'),
    
    # Takedown (Original - keep for backward compatibility)
    path('api/takedown/', views.takedown_scam, name='takedown_scam'),
    
    # USSD
    path('ussd-demo/', views.ussd_demo_page, name='ussd_demo'),
    path('ussd/callback/', ussd_handler.ussd_callback, name='ussd_callback'),
    path('ussd-test/', views.ussd_test_simulator, name='ussd_test'),
    path('ussd-analytics/', views.ussd_analytics, name='ussd_analytics'),
    
    # PWA
    path('manifest.json', views.serve_manifest, name='manifest'),
    path('sw.js', views.serve_service_worker, name='service_worker'),
    path('offline/', views.offline_page, name='offline'),
    
    # Corporate Shield
    path('corporate/', views.corporate_dashboard_page, name='corporate_page'),
    path('api/corporate/', views.corporate_dashboard, name='corporate_dashboard'),
    path('api/bulk-verify/', views.bulk_verify_numbers, name='bulk_verify'),
    path('api/generate-api-key/', views.generate_api_key, name='generate_api_key'),
    path('api/widget-code/', views.get_widget_code, name='widget_code'),
    path('corporate/upgrade/', views.corporate_upgrade_page, name='corporate_upgrade'),
    
    # Reports Dashboard
    path('reports-dashboard/', views.reports_dashboard, name='reports_dashboard'),
    
    # My Reports
    path('my-reports/', views.my_reports, name='my_reports'),
    
    # Authentication
    path('login/', views.login_page, name='login'),
    path('api/login/', views.api_login, name='api_login'),
    path('logout/', views.api_logout, name='logout'),
    
    # Profile
    path('profile/', views.profile_page, name='profile'),
    
    # Feedback
    path('api/feedback-stats/', views.feedback_stats, name='feedback_stats'),
    
    # Telegram Webhook
    path('webhook/telegram/', views.telegram_webhook, name='telegram_webhook'),
    
    # Push Notifications
    path('api/subscribe-push/', views.subscribe_push, name='subscribe_push'),
    
    # =========================
    # ENHANCEMENTS - Scam Alerts
    # =========================
    path('subscribe/', enhancements_views.subscribe_scam_alerts, name='subscribe_alerts'),
    path('unsubscribe/<str:token>/', enhancements_views.unsubscribe_scam_alerts, name='unsubscribe_alerts'),
    path('test-alert/', enhancements_views.test_scam_alert, name='test_alert'),
    path('api/scam-stats/', enhancements_views.get_scam_stats, name='scam_stats'),
    
    # =========================
    # ENHANCEMENTS - Takedown System (Enhanced)
    # =========================
    # Pages
    path('takedown/', enhancements_views.takedown_page, name='takedown_page'),
    
    # APIs
    path('api/takedown/submit/', enhancements_views.submit_takedown, name='submit_takedown'),
    path('api/takedown/stats/', enhancements_views.get_takedown_stats, name='takedown_stats'),
    path('api/takedown/reports/', enhancements_views.get_takedown_reports, name='takedown_reports'),
    path('api/takedown/update/', enhancements_views.update_takedown_status, name='update_takedown'),
    path('api/takedown/auto-process/', enhancements_views.auto_process_takedowns, name='auto_process_takedowns'),
    
    # =========================
    # ENHANCEMENTS - WhatsApp
    # =========================
    path('webhook/whatsapp/', enhancements_views.whatsapp_webhook, name='whatsapp_webhook'),
    
    # =========================
    # ENHANCEMENTS - ML
    # =========================
    path('api/train-enhanced/', enhancements_views.train_enhanced_model, name='train_enhanced'),
    path('api/predict-enhanced/', enhancements_views.predict_enhanced, name='predict_enhanced'),
    
    # =========================
    # ENHANCEMENTS - Analytics
    # =========================
    path('analytics/', enhancements_views.analytics_dashboard, name='analytics_dashboard'),
    path('api/analytics-data/', enhancements_views.analytics_data, name='analytics_data'),
    path('api/export-analytics-pdf/', enhancements_views.export_analytics_pdf, name='export_analytics_pdf'),
    
    # =========================
    # ENHANCEMENTS - Plan Upgrades (FIXED - Now pointing to enhancements_views)
    # =========================
    path('upgrade/', enhancements_views.upgrade_page, name='upgrade'),
    path('process-payment/', enhancements_views.process_payment, name='process_payment'),
    path('switch-to-free/', enhancements_views.switch_to_free, name='switch_to_free'),
    path('cancel-subscription/', enhancements_views.cancel_subscription, name='cancel_subscription'),
    path('api/usage-stats/', enhancements_views.get_usage_stats, name='usage_stats'),
    path('api/invoice/<str:invoice_id>/', enhancements_views.get_invoice, name='invoice'),
]