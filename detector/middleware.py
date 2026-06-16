# detector/middleware.py
from django.core.cache import cache
from django.http import JsonResponse
from datetime import datetime, timedelta

class RateLimitMiddleware:
    """Simple rate limiting without external packages"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Rate limit for API endpoints
        if request.path.startswith('/api/'):
            client_ip = self.get_client_ip(request)
            key = f'ratelimit_{client_ip}'
            
            # Get request count
            requests = cache.get(key, 0)
            
            if requests > 100:  # 100 requests per minute
                return JsonResponse({
                    'error': 'Rate limit exceeded. Please try again later.',
                    'retry_after': 60
                }, status=429)
            
            cache.set(key, requests + 1, timeout=60)
        
        return self.get_response(request)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

# ============================================================
# ADD THIS CORS MIDDLEWARE BELOW
# ============================================================

class CorsMiddleware:
    """Handle CORS preflight OPTIONS requests"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Handle OPTIONS request first
        if request.method == 'OPTIONS':
            response = JsonResponse({'status': 'ok'})
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
            response['Access-Control-Max-Age'] = '86400'  # Cache preflight for 24 hours
            return response
        
        # Process normal request
        response = self.get_response(request)
        
        # Add CORS headers to all responses
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        
        return response