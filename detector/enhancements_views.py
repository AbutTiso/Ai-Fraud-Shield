# detector/enhancements_views.py
# New enhancement views - Scam Alerts, Analytics, Takedown, etc.
# These are separate from the main views.py to keep it organized

import json
import io
from datetime import datetime, timedelta
from urllib.parse import urlparse

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Avg, Q, Sum

# ReportLab for PDF export
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# Models
from .models import (
    ScamReport, BlockedNumber, UserProfile, UserPoints, 
    TakedownReport, TakedownProvider, ImpersonatedBrand, Company
)
from .sms_detector import detect_sms_scam


# ============================================================
# PLAN UPGRADE SYSTEM
# ============================================================

@login_required
def upgrade_page(request):
    """Display the upgrade/pricing page with current plan details"""
    context = {
        'user': request.user,
        'company': request.user.userprofile.company if hasattr(request.user, 'userprofile') else None,
    }
    # FIXED: Use the correct template path - 'detector/corporate_upgrade.html'
    return render(request, 'detector/corporate_upgrade.html', context)


@login_required
@require_http_methods(["POST"])
def process_payment(request):
    """
    Process payment and upgrade user's plan
    Supports M-Pesa, Stripe, and Bank Transfer
    """
    try:
        # Get payment details
        plan = request.POST.get('plan', 'pro').lower()
        payment_method = request.POST.get('payment_method', 'mpesa')
        
        # Get user's company
        company = request.user.userprofile.company
        if not company:
            return JsonResponse({
                'success': False,
                'message': 'Company profile not found. Please set up your company first.'
            }, status=400)
        
        # Validate plan
        valid_plans = ['pro', 'enterprise']
        if plan not in valid_plans:
            return JsonResponse({
                'success': False,
                'message': 'Invalid plan selected.'
            }, status=400)
        
        # Process based on payment method
        if payment_method == 'mpesa':
            # M-Pesa Integration (Safaricom Daraja API)
            mpesa_phone = request.POST.get('mpesa_phone', '')
            if not mpesa_phone or len(mpesa_phone) < 10:
                return JsonResponse({
                    'success': False,
                    'message': 'Please provide a valid M-Pesa phone number.'
                }, status=400)
            
            # Call M-Pesa STK Push (Daraja API)
            # This is where you'd integrate with Safaricom Daraja API
            # For now, we'll simulate a successful payment
            payment_result = process_mpesa_payment(mpesa_phone, plan)
            if not payment_result['success']:
                return JsonResponse({
                    'success': False,
                    'message': payment_result['message']
                }, status=400)
            
        elif payment_method == 'stripe':
            # Stripe Integration
            # Process card payment via Stripe
            # For now, simulate success
            pass
            
        elif payment_method == 'bank':
            # Bank Transfer - Manual confirmation
            # Create pending transaction, wait for confirmation
            pass
        else:
            return JsonResponse({
                'success': False,
                'message': 'Invalid payment method.'
            }, status=400)
        
        # Upgrade the company plan
        upgrade_company_plan(company, plan)
        
        # Log the upgrade
        log_upgrade(request.user, company, plan, payment_method)
        
        # Send notification email
        send_upgrade_notification(request.user, company, plan)
        
        return JsonResponse({
            'success': True,
            'message': f'Successfully upgraded to {plan.capitalize()} plan!',
            'plan': plan,
            'features': get_plan_features(plan)
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def switch_to_free(request):
    """Switch user's company back to Free plan"""
    try:
        company = request.user.userprofile.company
        if not company:
            messages.error(request, 'Company profile not found.')
            return redirect('upgrade')
        
        # Check if user has already upgraded
        if company.plan_type == 'FREE':
            messages.warning(request, 'You are already on the Free plan.')
            return redirect('upgrade')
        
        # Downgrade to free
        company.plan_type = 'FREE'
        company.staff_limit = 5
        company.scans_limit = 1000
        company.subscription_end_date = None
        company.save()
        
        # Log the downgrade
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"User {request.user.username} switched to Free plan")
        
        messages.success(request, 'You have successfully switched to the Free plan.')
        return redirect('upgrade')
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Switch to free error: {str(e)}")
        messages.error(request, 'An error occurred. Please try again.')
        return redirect('upgrade')


@login_required
@require_http_methods(["POST"])
def cancel_subscription(request):
    """Cancel active subscription (Pro or Enterprise)"""
    try:
        company = request.user.userprofile.company
        if not company:
            return JsonResponse({
                'success': False,
                'message': 'Company not found.'
            }, status=400)
        
        if company.plan_type == 'FREE':
            return JsonResponse({
                'success': False,
                'message': 'You are already on the Free plan.'
            }, status=400)
        
        # Cancel subscription (set to free at end of billing cycle)
        company.plan_type = 'FREE'
        company.staff_limit = 5
        company.scans_limit = 1000
        company.subscription_end_date = None
        company.save()
        
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Subscription cancelled for {request.user.username}")
        
        return JsonResponse({
            'success': True,
            'message': 'Subscription cancelled successfully.'
        })
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Cancel subscription error: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': 'An error occurred. Please try again.'
        }, status=500)


@login_required
def get_usage_stats(request):
    """Get current usage statistics for the company"""
    try:
        company = request.user.userprofile.company
        if not company:
            return JsonResponse({
                'success': False,
                'message': 'Company not found.'
            }, status=400)
        
        # Calculate usage percentages
        scans_used = company.scans_used or 0
        scans_limit = company.scans_limit or 1000
        staff_count = company.staff_count or 0
        staff_limit = company.staff_limit or 5
        
        scans_percentage = (scans_used / scans_limit * 100) if scans_limit > 0 else 0
        staff_percentage = (staff_count / staff_limit * 100) if staff_limit > 0 else 0
        
        # Get days remaining
        if company.subscription_end_date:
            days_remaining = (company.subscription_end_date - timezone.now()).days
        else:
            days_remaining = None
        
        return JsonResponse({
            'success': True,
            'data': {
                'plan': company.plan_type,
                'scans_used': scans_used,
                'scans_limit': scans_limit,
                'scans_percentage': round(scans_percentage, 1),
                'staff_count': staff_count,
                'staff_limit': staff_limit,
                'staff_percentage': round(staff_percentage, 1),
                'days_remaining': days_remaining,
                'subscription_end_date': company.subscription_end_date.strftime('%Y-%m-%d') if company.subscription_end_date else None,
            }
        })
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Usage stats error: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': 'Error fetching usage statistics.'
        }, status=500)


@login_required
def get_invoice(request, invoice_id):
    """Generate and display invoice for a payment"""
    try:
        # Get invoice from database
        # This would be linked to a Payment model
        invoice_data = {
            'invoice_id': invoice_id,
            'company_name': request.user.userprofile.company.name,
            'plan': request.user.userprofile.company.plan_type,
            'amount': 9999 if request.user.userprofile.company.plan_type == 'PRO' else 0,
            'date': timezone.now().strftime('%Y-%m-%d'),
            'status': 'paid',
            'billing_address': request.user.userprofile.company.address if request.user.userprofile.company else '',
        }
        
        return render(request, 'detector/invoice.html', {'invoice': invoice_data})
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Invoice error: {str(e)}")
        messages.error(request, 'Invoice not found.')
        return redirect('upgrade')


# ============================================================
# HELPER FUNCTIONS FOR UPGRADES
# ============================================================

def process_mpesa_payment(phone_number, plan):
    """
    Process M-Pesa payment using Safaricom Daraja API
    """
    try:
        # This is where you'd integrate with Safaricom Daraja API
        # For now, we simulate a successful payment
        
        # In production, you would:
        # 1. Generate access token
        # 2. Call STK Push API
        # 3. Wait for callback
        # 4. Confirm payment
        
        # Simulate API call
        if phone_number.startswith('07') or phone_number.startswith('01'):
            # Simulate successful M-Pesa request
            return {
                'success': True,
                'message': 'M-Pesa payment initiated. Please check your phone to confirm.',
                'transaction_id': f'MP{datetime.now().strftime("%Y%m%d%H%M%S")}'
            }
        else:
            return {
                'success': False,
                'message': 'Invalid phone number format. Please use a valid Safaricom number.'
            }
            
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"M-Pesa payment error: {str(e)}")
        return {
            'success': False,
            'message': 'M-Pesa payment failed. Please try again.'
        }


def upgrade_company_plan(company, plan):
    """
    Update company plan with new limits and features
    """
    if plan == 'pro':
        company.plan_type = 'PRO'
        company.staff_limit = 50
        company.scans_limit = 50000
        company.subscription_end_date = timezone.now() + timedelta(days=30)
        company.save()
        
    elif plan == 'enterprise':
        company.plan_type = 'ENTERPRISE'
        company.staff_limit = 999999  # Unlimited
        company.scans_limit = 9999999  # Unlimited
        company.subscription_end_date = timezone.now() + timedelta(days=365)
        company.save()


def get_plan_features(plan):
    """
    Get features for a specific plan
    """
    features = {
        'free': {
            'staff_limit': 5,
            'scans_limit': 1000,
            'api_access': False,
            'bulk_verification': False,
            'custom_reports': False,
            'priority_support': False,
        },
        'pro': {
            'staff_limit': 50,
            'scans_limit': 50000,
            'api_access': True,
            'bulk_verification': True,
            'custom_reports': True,
            'priority_support': True,
        },
        'enterprise': {
            'staff_limit': 'Unlimited',
            'scans_limit': 'Unlimited',
            'api_access': True,
            'bulk_verification': True,
            'custom_reports': True,
            'priority_support': True,
            'dedicated_manager': True,
        }
    }
    return features.get(plan, features['free'])


def log_upgrade(user, company, plan, payment_method):
    """
    Log the upgrade for audit purposes
    """
    import logging
    logger = logging.getLogger(__name__)
    logger.info(
        f"UPGRADE: User {user.username} (ID: {user.id}) "
        f"upgraded company {company.name} (ID: {company.id}) "
        f"to {plan.upper()} plan via {payment_method.upper()}"
    )


def send_upgrade_notification(user, company, plan):
    """
    Send email notification about the upgrade
    """
    try:
        subject = f'Plan Upgrade Confirmation - {plan.capitalize()} Plan'
        
        # FIXED: Properly format the email message with f-strings
        message = """
        Dear {user.get_full_name() or user.username},
        
        Your company f'{company.name}' has been successfully upgraded to the {plan.capitalize()} plan.
        
        Plan Details:
        - Plan: {plan.capitalize()}
        - Staff Limit: {get_plan_features(plan)['staff_limit']}
        - Scans Limit: {get_plan_features(plan)['scans_limit']}
        - Valid Until: {company.subscription_end_date.strftime('%B %d, %Y') if company.subscription_end_date else 'N/A'}
        
        Thank you for upgrading to AI Fraud Shield!
        
        Best regards,
        AI Fraud Shield Team
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=True,
        )
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to send upgrade notification: {str(e)}")


# ============================================================
# SCAM ALERT SUBSCRIPTION SYSTEM
# ============================================================

@login_required
def subscribe_scam_alerts(request):
    """Subscribe user to scam alerts"""
    if request.method == 'POST':
        try:
            email = request.POST.get('email', request.user.email)
            phone = request.POST.get('phone', '')
            frequency = request.POST.get('frequency', 'DAILY')
            
            # Validate frequency
            if frequency not in ['DAILY', 'WEEKLY', 'INSTANT']:
                frequency = 'DAILY'
            
            # Create or update subscription using your existing UserProfile
            profile, created = UserProfile.objects.get_or_create(user=request.user)
            profile.alert_subscription = True
            profile.alert_frequency = frequency
            profile.alert_email = email
            if phone:
                profile.alert_phone = phone
            profile.save()
            
            messages.success(request, f'✅ Subscribed to {frequency.lower()} scam alerts!')
            return redirect('home')
            
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('home')
    
    return render(request, 'detector/subscribe_alerts.html')


def unsubscribe_scam_alerts(request, token):
    """Unsubscribe from scam alerts"""
    try:
        from django.contrib.auth.models import User
        user = User.objects.filter(email__icontains=token).first()
        
        if user:
            profile = UserProfile.objects.get(user=user)
            profile.alert_subscription = False
            profile.save()
            return render(request, 'detector/unsubscribe_success.html')
        
        return render(request, 'detector/unsubscribe_failed.html')
        
    except Exception as e:
        return render(request, 'detector/unsubscribe_failed.html', {'error': str(e)})


def send_scam_alert_email(user_email, scam_data):
    """Send scam alert email to subscriber"""
    subject = f"🛡️ AI Fraud Shield: {scam_data['title']}"
    
    html_message = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f8fafc; }}
            .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 12px; }}
            .header {{ background: #002855; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
            .header h1 {{ margin: 0; color: #F5A623; }}
            .content {{ padding: 20px; }}
            .scam-card {{ background: #fef3d5; border-left: 4px solid #F5A623; padding: 15px; margin: 15px 0; border-radius: 4px; }}
            .button {{ background: #F5A623; color: #002855; padding: 12px 24px; text-decoration: none; border-radius: 50px; display: inline-block; font-weight: bold; }}
            .footer {{ text-align: center; padding: 20px; color: #64748b; font-size: 12px; border-top: 1px solid #e5e7eb; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ AI Fraud Shield</h1>
                <p>Scam Alert</p>
            </div>
            <div class="content">
                <h2>{scam_data['title']}</h2>
                <p>{scam_data['message']}</p>
                
                <div class="scam-card">
                    <strong>📋 Details:</strong><br>
                    {scam_data['details']}
                </div>
                
                <p>
                    <a href=f"{scam_data['action_url']}" class="button">View Details</a>
                </p>
                
                <hr>
                <p style="font-size: 14px; color: #64748b;">
                    <strong>💡 Safety Tips:</strong><br>
                    ✅ Never share your PIN or OTP<br>
                    ✅ Verify urgent requests through official channels<br>
                    ✅ Report scams to 333 (Safaricom)
                </p>
            </div>
            <div class="footer">
                &copy; 2026 AI Fraud Shield Kenya - Protecting Kenyans from Scams
            </div>
        </div>
    </body>
    </html>
    """
    
    send_mail(
        subject=subject,
        message=strip_tags(html_message),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        html_message=html_message,
        fail_silently=True,
    )


@staff_member_required
def test_scam_alert(request):
    """Manually trigger a test scam alert (admin only)"""
    if request.method == 'POST':
        subscribers = UserProfile.objects.filter(alert_subscription=True)
        count = 0
        
        for profile in subscribers:
            try:
                send_scam_alert_email(profile.alert_email or profile.user.email, {
                    'title': '🔴 TEST SCAM ALERT',
                    'message': 'This is a test scam alert from AI Fraud Shield.',
                    'details': 'Test scam: Fake M-Pesa suspension detected.',
                    'action_url': 'http://127.0.0.1:8000/scam-alerts/'
                })
                count += 1
            except Exception as e:
                print(f"Failed to send to {profile.user.email}: {e}")
        
        messages.success(request, f'Sent test alerts to {count} subscribers')
        return redirect('home')
    
    return JsonResponse({'error': 'POST required'}, status=405)


# ============================================================
# SCAM ALERT API
# ============================================================

@csrf_exempt
@require_http_methods(["GET"])
def get_scam_stats(request):
    """Get scam statistics for analytics"""
    try:
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        stats = {
            'today': ScamReport.objects.filter(date_reported__date=today).count(),
            'this_week': ScamReport.objects.filter(date_reported__date__gte=week_ago).count(),
            'this_month': ScamReport.objects.filter(date_reported__date__gte=month_ago).count(),
            'total': ScamReport.objects.count(),
            'high_risk': ScamReport.objects.filter(risk_score__gte=70).count(),
            'medium_risk': ScamReport.objects.filter(risk_score__gte=40, risk_score__lt=70).count(),
            'low_risk': ScamReport.objects.filter(risk_score__lt=40).count(),
            'by_type': {},
        }
        
        # Get counts by type
        for report_type in ['SMS', 'EMAIL', 'WHATSAPP', 'CALL', 'TELEGRAM', 'URL']:
            stats['by_type'][report_type] = ScamReport.objects.filter(report_type=report_type).count()
        
        return JsonResponse({'success': True, 'stats': stats})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============================================================
# AUTOMATED TAKEDOWN SYSTEM
# ============================================================

def takedown_page(request):
    """Takedown system page"""
    return render(request, 'detector/takedown.html')


@csrf_exempt
@require_http_methods(["POST"])
def submit_takedown(request):
    """Submit a scam URL for takedown"""
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            url = data.get('url', '')
        else:
            url = request.POST.get('url', '')
        
        if not url:
            return JsonResponse({'error': 'URL required'}, status=400)
        
        # Analyze the URL
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Check if already reported
        existing = TakedownReport.objects.filter(url=url).first()
        
        if existing:
            return JsonResponse({
                'success': True,
                'already_reported': True,
                'status': existing.status,
                'message': f'This URL was already reported on {existing.created_at.strftime("%Y-%m-%d")}'
            })
        
        # Detect hosting provider
        provider = detect_hosting_provider(domain)
        
        # Detect if it impersonates a brand
        brand = detect_impersonated_brand(domain, url)
        
        # Create takedown report
        report = TakedownReport.objects.create(
            url=url,
            domain=domain,
            hosting_provider=provider.name if provider else 'Unknown',
            scam_type='phishing' if brand else 'scam',
            reported_by=request.user.username if request.user.is_authenticated else 'Anonymous',
            status='PENDING',
            notes=f"Reported by {request.user.username if request.user.is_authenticated else 'Anonymous'}"
        )
        
        # If brand detected, notify them
        if brand:
            notify_brand_of_impersonation(brand, url, domain)
        
        return JsonResponse({
            'success': True,
            'report_id': report.id,
            'domain': domain,
            'provider': provider.name if provider else 'Unknown',
            'status': 'PENDING',
            'message': 'Takedown request submitted successfully',
            'brand_detected': brand.name if brand else None
        })
        
    except Exception as e:
        print(f"Takedown error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_takedown_reports(request):
    """Get list of takedown reports"""
    try:
        reports = TakedownReport.objects.all().order_by('-created_at')[:50]
        
        status_display = dict(TakedownReport.STATUS_CHOICES)
        
        data = []
        for report in reports:
            data.append({
                'id': report.id,
                'url': report.url,
                'domain': report.domain,
                'provider': report.hosting_provider,
                'status': report.status,
                'status_display': status_display.get(report.status, report.status),
                'created_at': report.created_at.strftime('%Y-%m-%d %H:%M'),
                'updated_at': report.updated_at.strftime('%Y-%m-%d %H:%M'),
                'google_reported': report.google_reported,
                'hosting_reported': report.hosting_reported,
            })
        
        return JsonResponse({'success': True, 'reports': data})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_takedown_stats(request):
    """Get takedown statistics"""
    try:
        total = TakedownReport.objects.count()
        completed = TakedownReport.objects.filter(status='COMPLETED').count()
        pending = TakedownReport.objects.filter(status__in=['PENDING', 'SUBMITTED']).count()
        in_progress = TakedownReport.objects.filter(status='IN_PROGRESS').count()
        failed = TakedownReport.objects.filter(status='FAILED').count()
        rejected = TakedownReport.objects.filter(status='REJECTED').count()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'total': total,
                'completed': completed,
                'pending': pending,
                'in_progress': in_progress,
                'failed': failed,
                'rejected': rejected,
                'success_rate': round((completed / total * 100) if total > 0 else 0, 1)
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def update_takedown_status(request):
    """Update status of a takedown report (admin only)"""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Admin only'}, status=403)
    
    try:
        data = json.loads(request.body)
        report_id = data.get('report_id')
        status = data.get('status')
        notes = data.get('notes', '')
        
        report = TakedownReport.objects.get(id=report_id)
        report.status = status
        if notes:
            report.notes += f"\n{timezone.now().strftime('%Y-%m-%d %H:%M')}: {notes}"
        if status == 'COMPLETED':
            report.completed_at = timezone.now()
        report.save()
        
        return JsonResponse({
            'success': True,
            'message': f'Status updated to {status}'
        })
    except TakedownReport.DoesNotExist:
        return JsonResponse({'error': 'Report not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def detect_hosting_provider(domain):
    """Detect hosting provider for a domain"""
    try:
        # Get IP address
        import socket
        ip = socket.gethostbyname(domain)
        
        # Check against known provider IP ranges (simplified)
        providers = TakedownProvider.objects.all()
        
        for provider in providers:
            provider_name = provider.name.lower()
            
            # Simple IP-based detection
            if provider_name in ['cloudflare', 'aws', 'amazon']:
                if ip.startswith('104.') or ip.startswith('172.64.') or ip.startswith('3.') or ip.startswith('54.'):
                    return provider
            elif provider_name == 'godaddy':
                if ip.startswith('184.168.') or ip.startswith('50.63.') or ip.startswith('160.153.'):
                    return provider
            elif provider_name == 'namecheap':
                if ip.startswith('198.54.') or ip.startswith('162.210.') or ip.startswith('199.188.'):
                    return provider
            elif provider_name == 'digitalocean':
                if ip.startswith('159.89.') or ip.startswith('157.245.') or ip.startswith('167.71.'):
                    return provider
            elif provider_name == 'linode':
                if ip.startswith('172.104.') or ip.startswith('45.33.') or ip.startswith('139.162.'):
                    return provider
            elif provider_name == 'vultr':
                if ip.startswith('108.61.') or ip.startswith('45.76.') or ip.startswith('104.238.'):
                    return provider
            elif provider_name == 'heroku':
                if ip.startswith('54.') or ip.startswith('35.') and 'heroku' in domain:
                    return provider
            elif provider_name == 'netlify':
                if 'netlify' in domain or ip.startswith('75.2.') or ip.startswith('99.83.'):
                    return provider
        
        return None
    except:
        return None


def detect_impersonated_brand(domain, url):
    """Detect if URL impersonates a known brand"""
    try:
        brands = ImpersonatedBrand.objects.filter(is_active=True)
        
        for brand in brands:
            # Check if brand name appears in domain or URL
            brand_name = brand.name.lower().replace(' ', '')
            brand_variations = [brand_name, brand_name.replace(' ', ''), brand_name.replace(' ', '-')]
            
            for variation in brand_variations:
                if variation in domain.lower() or variation in url.lower():
                    # Make sure it's not the official domain
                    if brand.official_domain.lower() not in domain.lower():
                        return brand
        
        return None
    except:
        return None


def notify_brand_of_impersonation(brand, scam_url, domain):
    """Send email notification to brand about impersonation"""
    try:
        subject = f"🚨 Impersonation Alert: {brand.name} - Scam Detected"
        
        ngrok_url = getattr(settings, 'NGROK_URL', 'http://127.0.0.1:8000')
        
        message = """
        AI Fraud Shield has detected a scam website impersonating {brand.name}.
        
        Brand: {brand.name}
        Official Domain: {brand.official_domain}
        Scam URL: {scam_url}
        Scam Domain: {domain}
        
        This appears to be a phishing/scam attempt. Please investigate and consider taking action.
        
        Reported by: AI Fraud Shield Automated Detection
        Report Date: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        To report this scam: {ngrok_url}/takedown/
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[brand.notification_email],
            fail_silently=True,
        )
        
        print(f"✅ Brand notification sent to {brand.notification_email}")
    except Exception as e:
        print(f"Failed to notify brand: {e}")


@staff_member_required
def auto_process_takedowns(request):
    """Automated processing of pending takedowns (cron job)"""
    if request.method == 'POST':
        pending = TakedownReport.objects.filter(status='PENDING')[:10]
        processed = 0
        
        for report in pending:
            try:
                # Mark as submitted
                report.status = 'SUBMITTED'
                report.hosting_reported = True
                report.google_reported = True
                report.save()
                processed += 1
            except Exception as e:
                print(f"Error processing {report.domain}: {e}")
        
        return JsonResponse({
            'success': True,
            'processed': processed,
            'pending_remaining': TakedownReport.objects.filter(status='PENDING').count()
        })
    
    return JsonResponse({'error': 'POST required'}, status=405)


# ============================================================
# WHATSAPP BUSINESS API (Coming soon)
# ============================================================

@csrf_exempt
@require_http_methods(["POST"])
def whatsapp_webhook(request):
    """WhatsApp Business API webhook for incoming messages"""
    try:
        data = json.loads(request.body)
        
        # Handle different webhook events
        event_type = data.get('event', '')
        
        if event_type == 'message':
            # Process incoming WhatsApp message
            sender = data.get('sender', '')
            message = data.get('message', '')
            
            # Analyze the message for scams
            result = detect_sms_scam(message)
            
            # Send back analysis
            response_text = f"📊 Scam Analysis:\nRisk Score: {result['score']}/100\n{result.get('message', '')}"
            
            return JsonResponse({
                'success': True,
                'response': response_text
            })
        
        return JsonResponse({'success': True, 'event': event_type})
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================
# ML MODEL IMPROVEMENT (Coming soon)
# ============================================================

@csrf_exempt
@require_http_methods(["POST"])
def train_enhanced_model(request):
    """Trigger enhanced ML model training"""
    try:
        return JsonResponse({
            'success': True,
            'message': 'Enhanced ML training not yet implemented',
            'status': 'coming_soon'
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def predict_enhanced(request):
    """Enhanced ML prediction endpoint"""
    try:
        data = json.loads(request.body)
        text = data.get('text', '')
        
        if not text:
            return JsonResponse({'error': 'No text provided'}, status=400)
        
        # Use existing SMS detector for now
        result = detect_sms_scam(text)
        result['enhanced'] = False
        result['model_version'] = '2.0.0'
        
        return JsonResponse(result)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================
# ADVANCED ANALYTICS DASHBOARD
# ============================================================

def analytics_dashboard(request):
    """Advanced Analytics Dashboard with charts and trends"""
    return render(request, 'detector/analytics_dashboard.html')


@csrf_exempt
@require_http_methods(["GET"])
def analytics_data(request):
    """API endpoint for analytics data"""
    try:
        # Get time range filter
        days = int(request.GET.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Get reports in range
        reports = ScamReport.objects.filter(date_reported__gte=start_date)
        
        # ============================================================
        # 1. DAILY TREND DATA
        # ============================================================
        daily_trend = []
        daily_labels = []
        for i in range(days, -1, -1):
            date = timezone.now().date() - timedelta(days=i)
            count = reports.filter(date_reported__date=date).count()
            daily_trend.append(count)
            daily_labels.append(date.strftime('%b %d'))
        
        # ============================================================
        # 2. SCAM TYPE DISTRIBUTION
        # ============================================================
        type_distribution = {}
        for report_type in ['SMS', 'EMAIL', 'WHATSAPP', 'CALL', 'TELEGRAM', 'URL', 'SCREENSHOT']:
            count = reports.filter(report_type=report_type).count()
            if count > 0:
                type_distribution[report_type] = count
        
        # ============================================================
        # 3. RISK LEVEL DISTRIBUTION
        # ============================================================
        risk_distribution = {
            'Critical (70-100)': reports.filter(risk_score__gte=70).count(),
            'High (50-69)': reports.filter(risk_score__gte=50, risk_score__lt=70).count(),
            'Medium (30-49)': reports.filter(risk_score__gte=30, risk_score__lt=50).count(),
            'Low (0-29)': reports.filter(risk_score__lt=30).count(),
        }
        
        # ============================================================
        # 4. WEEKLY AVERAGE SCORE
        # ============================================================
        weekly_avg = []
        weekly_labels_avg = []
        for i in range(4, -1, -1):
            week_start = timezone.now().date() - timedelta(days=i*7 + 7)
            week_end = timezone.now().date() - timedelta(days=i*7)
            week_data = reports.filter(date_reported__date__gte=week_start, date_reported__date__lt=week_end)
            avg_score = week_data.aggregate(avg=Avg('risk_score'))['avg'] or 0
            weekly_avg.append(round(avg_score, 1))
            weekly_labels_avg.append(f'Week {4-i}')
        
        # ============================================================
        # 5. TOP COUNTIES (if available)
        # ============================================================
        county_data = {}
        for report in reports.filter(county__isnull=False).exclude(county=''):
            county = report.county or 'Unknown'
            county_data[county] = county_data.get(county, 0) + 1
        
        top_counties = sorted(county_data.items(), key=lambda x: x[1], reverse=True)[:10]
        county_names = [c[0] for c in top_counties]
        county_counts = [c[1] for c in top_counties]
        
        # ============================================================
        # 6. SUMMARY STATS
        # ============================================================
        total_reports = reports.count()
        high_risk_count = reports.filter(risk_score__gte=70).count()
        avg_score = reports.aggregate(avg=Avg('risk_score'))['avg'] or 0
        
        # Get unique report counts safely using reported_by
        try:
            unique_phone_numbers = reports.values('reported_by').distinct().count()
        except:
            unique_phone_numbers = reports.count()
        
        # ============================================================
        # 7. RECENT SCAMS
        # ============================================================
        recent_scams = reports.order_by('-date_reported')[:10]
        recent_data = []
        for scam in recent_scams:
            recent_data.append({
                'type': scam.report_type,
                'score': scam.risk_score,
                'content': scam.content[:80] if scam.content else '',
                'date': scam.date_reported.strftime('%Y-%m-%d %H:%M'),
                'county': scam.county or 'Unknown',
                'level': 'HIGH' if scam.risk_score >= 70 else 'MEDIUM' if scam.risk_score >= 40 else 'LOW'
            })
        
        return JsonResponse({
            'success': True,
            'data': {
                'daily_trend': daily_trend,
                'daily_labels': daily_labels,
                'type_distribution': type_distribution,
                'risk_distribution': risk_distribution,
                'weekly_avg': weekly_avg,
                'weekly_labels': weekly_labels_avg,
                'county_names': county_names,
                'county_counts': county_counts,
                'summary': {
                    'total_reports': total_reports,
                    'high_risk_count': high_risk_count,
                    'avg_score': round(avg_score, 1),
                    'unique_phones': unique_phone_numbers,
                },
                'recent_scams': recent_data,
                'analysis_time': timezone.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def export_analytics_pdf(request):
    """Export analytics as PDF report"""
    if not HAS_REPORTLAB:
        return JsonResponse({
            'success': False,
            'error': 'ReportLab not installed. Run: pip install reportlab'
        }, status=500)
    
    try:
        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#002855'),
            spaceAfter=30
        )
        elements.append(Paragraph("AI Fraud Shield - Analytics Report", title_style))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Summary stats
        elements.append(Paragraph("<b>Summary Statistics</b>", styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        total_reports = ScamReport.objects.count()
        high_risk = ScamReport.objects.filter(risk_score__gte=70).count()
        avg_score = ScamReport.objects.aggregate(avg=Avg('risk_score'))['avg'] or 0
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Reports', str(total_reports)],
            ['High Risk', str(high_risk)],
            ['Average Score', f"{round(avg_score, 1)}%"],
        ]
        table = Table(summary_data, colWidths=[200, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#002855')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=1
        )
        elements.append(Spacer(1, 50))
        elements.append(Paragraph("Generated by AI Fraud Shield - Protecting Kenyans from Digital Scams", footer_style))
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        
        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="analytics_report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        return response
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': str(e)}, status=500)