# detector/api/views.py
import json
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse

# Store API keys (in production, use database)
API_KEYS = {
    'test_key_123': {'tier': 'free', 'requests': 0, 'limit': 100},
    'demo_key': {'tier': 'free', 'requests': 0, 'limit': 100},
}

def check_api_key(request):
    """Validate API key from request header"""
    api_key = request.headers.get('X-API-Key', '') or request.GET.get('api_key', '')
    
    if not api_key:
        return None, "Missing API key. Include 'X-API-Key' header or 'api_key' parameter."
    
    if api_key not in API_KEYS:
        return None, "Invalid API key."
    
    key_data = API_KEYS[api_key]
    if key_data['requests'] >= key_data['limit']:
        return None, f"Rate limit exceeded ({key_data['limit']} requests/day)."
    
    key_data['requests'] += 1
    return api_key, None


@csrf_exempt
@require_http_methods(["POST", "GET"])
def check_sms(request):
    """Check SMS text for scams"""
    api_key, error = check_api_key(request)
    if error:
        return JsonResponse({'error': error}, status=401)
    
    if request.method == "GET":
        return JsonResponse({
            'endpoint': '/api/v1/check/sms',
            'method': 'POST',
            'description': 'Check SMS text for scam indicators',
            'parameters': {'text': 'SMS message text to analyze'},
            'example': 'curl -X POST /api/v1/check/sms -H "X-API-Key: test_key_123" -d "text=Your message"'
        })
    
    text = request.POST.get('text', '') or (json.loads(request.body).get('text', '') if request.body else '')
    
    if not text:
        return JsonResponse({'error': 'No text provided'}, status=400)
    
    from detector.views import detect_sms_scam
    result = detect_sms_scam(text)
    
    return JsonResponse({
        'success': True,
        'score': result.get('score', 0),
        'risk_level': result.get('risk_level', 'Unknown'),
        'is_scam': result.get('score', 0) >= 50,
        'warnings': result.get('warnings', [])[:5],
        'recommendations': result.get('recommendations', [])[:3],
        'analyzed_at': datetime.now().isoformat()
    })


@csrf_exempt
@require_http_methods(["POST", "GET"])
def check_phone(request):
    """Check phone number reputation"""
    api_key, error = check_api_key(request)
    if error:
        return JsonResponse({'error': error}, status=401)
    
    if request.method == "GET":
        return JsonResponse({
            'endpoint': '/api/v1/check/phone',
            'method': 'POST',
            'description': 'Check if a phone number is in the scam blocklist',
            'parameters': {'phone': 'Phone number to check (e.g., 0712345678)'}
        })
    
    phone = request.POST.get('phone', '') or (json.loads(request.body).get('phone', '') if request.body else '')
    
    if not phone:
        return JsonResponse({'error': 'No phone number provided'}, status=400)
    
    # Clean number
    cleaned = phone.strip().replace('-', '').replace(' ', '').replace('+', '')
    if cleaned.startswith('0'):
        cleaned = '254' + cleaned[1:]
    
    from detector.models import BlockedNumber
    try:
        entry = BlockedNumber.objects.get(phone_number=cleaned)
        return JsonResponse({
            'phone': cleaned,
            'found': True,
            'is_blocked': entry.status in ['CONFIRMED', 'BLOCKED'],
            'report_count': entry.report_count,
            'confidence': round(entry.confidence_score, 1),
            'status': entry.status,
            'category': entry.scam_category
        })
    except BlockedNumber.DoesNotExist:
        return JsonResponse({
            'phone': cleaned,
            'found': False,
            'is_blocked': False
        })


@csrf_exempt
@require_http_methods(["POST", "GET"])
def check_url(request):
    """Check URL safety"""
    api_key, error = check_api_key(request)
    if error:
        return JsonResponse({'error': error}, status=401)
    
    if request.method == "GET":
        return JsonResponse({
            'endpoint': '/api/v1/check/url',
            'method': 'POST',
            'description': 'Check if a URL is safe or phishing',
            'parameters': {'url': 'URL to check'}
        })
    
    url = request.POST.get('url', '') or (json.loads(request.body).get('url', '') if request.body else '')
    
    if not url:
        return JsonResponse({'error': 'No URL provided'}, status=400)
    
    from detector.views import check_url as url_check
    # Call the existing URL checker
    from django.test import RequestFactory
    factory = RequestFactory()
    fake_request = factory.post('/api/check-url/', data=json.dumps({'url': url}), content_type='application/json')
    result = url_check(fake_request)
    data = json.loads(result.content)
    
    return JsonResponse({
        'url': url,
        'score': data.get('score', 0),
        'risk_level': data.get('risk_level', 'Unknown'),
        'is_safe': data.get('score', 100) < 30,
        'warnings': data.get('warnings', []),
        'analyzed_at': datetime.now().isoformat()
    })


@csrf_exempt
@require_http_methods(["GET"])
def api_stats(request):
    """Get public statistics"""
    api_key, error = check_api_key(request)
    if error:
        return JsonResponse({'error': error}, status=401)
    
    from detector.models import ScamReport, BlockedNumber
    from django.utils import timezone
    
    total = ScamReport.objects.count() if ScamReport.objects else 0
    today = ScamReport.objects.filter(date_reported__date=timezone.now().date()).count() if ScamReport.objects else 0
    blocked = BlockedNumber.objects.filter(status__in=['CONFIRMED', 'BLOCKED']).count()
    
    return JsonResponse({
        'total_reports': total,
        'today_reports': today,
        'blocked_numbers': blocked,
        'updated_at': datetime.now().isoformat()
    })


@csrf_exempt
@require_http_methods(["POST", "GET"])
def api_report(request):
    """Report a scam number"""
    api_key, error = check_api_key(request)
    if error:
        return JsonResponse({'error': error}, status=401)
    
    if request.method == "GET":
        return JsonResponse({
            'endpoint': '/api/v1/report',
            'method': 'POST',
            'description': 'Report a scam phone number',
            'parameters': {'phone': 'Scam phone number', 'category': 'Scam type (optional)'}
        })
    
    phone = request.POST.get('phone', '') or (json.loads(request.body).get('phone', '') if request.body else '')
    category = request.POST.get('category', 'API Report') or (json.loads(request.body).get('category', 'API Report') if request.body else 'API Report')
    
    if not phone:
        return JsonResponse({'error': 'No phone number provided'}, status=400)
    
    cleaned = phone.strip().replace('-', '').replace(' ', '').replace('+', '')
    if cleaned.startswith('0'):
        cleaned = '254' + cleaned[1:]
    
    from detector.models import BlockedNumber
    entry, created = BlockedNumber.objects.get_or_create(
        phone_number=cleaned,
        defaults={'report_count': 1, 'scam_category': category, 'reported_by': f'api:{api_key}'}
    )
    if not created:
        entry.report_count += 1
        entry.save(update_fields=['report_count'])
    
    return JsonResponse({
        'success': True,
        'phone': cleaned,
        'report_count': entry.report_count,
        'reported_at': datetime.now().isoformat()
    })


@csrf_exempt
@require_http_methods(["GET"])
def api_blocklist(request):
    """Get top scam numbers"""
    api_key, error = check_api_key(request)
    if error:
        return JsonResponse({'error': error}, status=401)
    
    limit = int(request.GET.get('limit', 20))
    
    from detector.models import BlockedNumber
    numbers = BlockedNumber.objects.filter(
        status__in=['CONFIRMED', 'BLOCKED']
    ).order_by('-confidence_score')[:limit]
    
    return JsonResponse({
        'count': numbers.count(),
        'blocklist': [
            {
                'phone': n.phone_number,
                'reports': n.report_count,
                'confidence': round(n.confidence_score, 1),
                'category': n.scam_category
            }
            for n in numbers
        ],
        'updated_at': datetime.now().isoformat()
    })


def api_docs(request):
    """API documentation page"""
    docs = {
        'name': 'AI Fraud Shield API',
        'version': '1.0',
        'base_url': request.build_absolute_uri('/api/v1/'),
        'authentication': 'Include X-API-Key header with your API key',
        'test_key': 'test_key_123 (100 requests/day)',
        'endpoints': {
            'POST /check/sms': 'Check SMS text for scams',
            'POST /check/phone': 'Check phone number reputation',
            'POST /check/url': 'Check URL safety',
            'GET /stats': 'Get scam statistics',
            'POST /report': 'Report a scam number',
            'GET /blocklist': 'Get top scam numbers',
        },
        'example': 'curl -X POST {base}/check/sms -H "X-API-Key: test_key_123" -H "Content-Type: application/json" -d \'{"text":"Your SMS message"}\''
    }
    return JsonResponse(docs)

def api_docs(request):
    """API documentation page - HTML version"""
    # If browser requests HTML, return nice page
    accept = request.headers.get('Accept', '')
    if 'text/html' in accept or 'api_key' not in request.GET:
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AI Fraud Shield API v1.0</title>
            <style>
                body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #f8fafc; color: #1e293b; }
                h1 { color: #002855; border-bottom: 3px solid #f5a623; padding-bottom: 10px; }
                .endpoint { background: white; border-radius: 10px; padding: 20px; margin: 15px 0; border-left: 4px solid #6366f1; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                .method { display: inline-block; padding: 4px 10px; border-radius: 5px; font-weight: bold; font-size: 0.85rem; margin-right: 10px; }
                .post { background: #10b981; color: white; }
                .get { background: #3b82f6; color: white; }
                .url { font-family: monospace; font-size: 1rem; }
                .desc { color: #64748b; margin: 8px 0; }
                .example { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 0.8rem; margin-top: 10px; overflow-x: auto; }
                .key { background: #fef3d5; padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #f5a623; }
                a { color: #6366f1; }
            </style>
        </head>
        <body>
            <h1>🛡️ AI Fraud Shield API v1.0</h1>
            <p>REST API for scam detection. Integrate into your apps, websites, or services.</p>
            
            <div class="key">
                <strong>🔑 Authentication:</strong> Include <code>X-API-Key</code> header<br>
                <strong>Test Key:</strong> <code>test_key_123</code> (100 requests/day free)<br>
                <strong>Base URL:</strong> <code>""" + request.build_absolute_uri('/api/v1/') + """</code>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span><span class="url">/check/sms</span>
                <p class="desc">Check SMS text for scam indicators. Returns risk score, warnings, and recommendations.</p>
                <div class="example">curl -X POST """ + request.build_absolute_uri('/api/v1/check/sms') + """ \\
  -H "X-API-Key: test_key_123" \\
  -H "Content-Type: application/json" \\
  -d f'{"text":"URGENT: Your M-Pesa has been suspended. Send PIN!"}'</div>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span><span class="url">/check/phone</span>
                <p class="desc">Check phone number reputation in the blocklist.</p>
                <div class="example">curl -X POST """ + request.build_absolute_uri('/api/v1/check/phone') + """ \\
  -H "X-API-Key: test_key_123" \\
  -H "Content-Type: application/json" \\
  -d f'{"phone":"0712345678"}'</div>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span><span class="url">/check/url</span>
                <p class="desc">Check if a URL is safe or potentially dangerous.</p>
                <div class="example">curl -X POST """ + request.build_absolute_uri('/api/v1/check/url') + """ \\
  -H "X-API-Key: test_key_123" \\
  -d "url=https://suspicious-site.com"</div>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span><span class="url">/stats</span>
                <p class="desc">Get public scam statistics.</p>
                <div class="example">curl """ + request.build_absolute_uri('/api/v1/stats') + """ \\
  -H "X-API-Key: test_key_123"</div>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span><span class="url">/report</span>
                <p class="desc">Report a scam phone number to the blocklist.</p>
                <div class="example">curl -X POST """ + request.build_absolute_uri('/api/v1/report') + """ \\
  -H "X-API-Key: test_key_123" \\
  -d "phone=0712345678&category=M-Pesa Scam"</div>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span><span class="url">/blocklist</span>
                <p class="desc">Get top reported scam numbers.</p>
                <div class="example">curl """ + request.build_absolute_uri('/api/v1/blocklist') + """ \\
  -H "X-API-Key: test_key_123"</div>
            </div>
            
            <p style="text-align:center;margin-top:30px;color:#64748b;">
                🛡️ AI Fraud Shield | <a href="/">Dashboard</a> | <a href="/api/v1/?format=json">JSON Format</a>
            </p>
        </body>
        </html>
        """
        return HttpResponse(html)
    
    # JSON format for API clients
    return JsonResponse({
        'name': 'AI Fraud Shield API',
        'version': '1.0',
        'base_url': request.build_absolute_uri('/api/v1/'),
        'authentication': 'Include X-API-Key header with your API key',
        'test_key': 'test_key_123 (100 requests/day)',
        'endpoints': {
            'POST /check/sms': 'Check SMS text for scams',
            'POST /check/phone': 'Check phone number reputation',
            'POST /check/url': 'Check URL safety',
            'GET /stats': 'Get scam statistics',
            'POST /report': 'Report a scam number',
            'GET /blocklist': 'Get top scam numbers',
        }
    })