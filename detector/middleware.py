# detector/middleware.py
from django.core.cache import cache
from django.http import JsonResponse
from django.conf import settings
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
# CORS MIDDLEWARE
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


# ============================================================
# NO-CACHE MIDDLEWARE (ADD THIS - FIXES 304 ISSUES)
# ============================================================

class NoCacheMiddleware:
    """
    Middleware to add no-cache headers to all responses in development.
    Prevents 304 Not Modified responses and forces fresh loading.
    This fixes the caching issues where features don't appear until refresh.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Only add no-cache headers in development
        if settings.DEBUG:
            # Add headers to prevent any caching
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
            
            # Remove ETag to prevent 304 responses
            if 'ETag' in response:
                del response['ETag']
            
            # For static files specifically
            if request.path.startswith('/static/'):
                response['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
                response['Pragma'] = 'no-cache'
                response['Expires'] = '0'
        
        return response


# ============================================================
# SECURITY MIDDLEWARE (OPTIONAL - FOR PRODUCTION)
# ============================================================

class SecurityHeadersMiddleware:
    """
    Add security headers to all responses.
    Should be used in production.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Only add security headers in production
        if not settings.DEBUG:
            # Security headers
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            response['X-XSS-Protection'] = '1; mode=block'
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            # Content Security Policy (adjust as needed)
            response['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                "font-src 'self' https://cdnjs.cloudflare.com; "
                "img-src 'self' data:; "
                "connect-src 'self' https://api.telegram.org;"
            )
        
        return response


# ============================================================
# COMPRESSION MIDDLEWARE (OPTIONAL - FOR PERFORMANCE)
# ============================================================

class GzipCompressionMiddleware:
    """
    Simple gzip compression for responses.
    Use django's built-in GZipMiddleware instead in production.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Check if client accepts gzip
        accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')
        if 'gzip' in accept_encoding:
            # Let Django's GZipMiddleware handle this
            # This is just a placeholder
            pass
        
        return response