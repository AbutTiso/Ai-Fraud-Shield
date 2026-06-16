import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-fallback-key-for-dev')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'True') == 'True'

ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    'fog-compound-brilliant.ngrok-free.dev',
    '.ngrok-free.dev',  
]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'detector',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'detector.middleware.CorsMiddleware',
    'detector.middleware.RateLimitMiddleware',
    'detector.middleware.NoCacheMiddleware',  # Add this for development
]

ROOT_URLCONF = 'fraudshield.urls'

# ============ TEMPLATES - FIXED ============
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,  # Keep as True
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.debug',
            ],
            # DO NOT add 'loaders' here - it conflicts with APP_DIRS
        },
    },
]

WSGI_APPLICATION = 'fraudshield.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Nairobi'
USE_I18N = True
USE_TZ = True

# ============ AUTHENTICATION SETTINGS ============
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

# ============ EMAIL SETTINGS ============
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
DEFAULT_FROM_EMAIL = 'noreply@aifraudshield.com'
CONTACT_EMAIL = 'admin@aifraudshield.com'

# ============ USSD SETTINGS ============
USSD_SERVICE_CODE = os.getenv('USSD_SERVICE_CODE', '*483*72#')

# ============ STATIC FILES ============
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'detector' / 'static',
]

# ============ STATIC FILES CACHE CONTROL ============
if DEBUG:
    # Disable ETags to prevent 304 responses
    USE_ETAGS = False
    
    # Static files storage - no caching
    STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ============ RATE LIMITING ============
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day',
    }
}

# ============ CACHING ============
if DEBUG:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'unique-snowflake',
            'TIMEOUT': 300,
        }
    }

# ============ LOGGING ============
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'fraudshield.log',
        },
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'detector': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
        },
    },
}

# ============ THIRD PARTY API KEYS ============
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
AT_USERNAME = os.getenv('AT_USERNAME', 'sandbox')
AT_API_KEY = os.getenv('AT_API_KEY', '')
AT_SHORTCODE = os.getenv('AT_SHORTCODE', '4350')
NGROK_URL = os.getenv('NGROK_URL')
VAPID_PUBLIC_KEY = os.getenv('VAPID_PUBLIC_KEY')
VAPID_PRIVATE_KEY = os.getenv('VAPID_PRIVATE_KEY')
VAPID_SUBJECT = os.getenv('VAPID_SUBJECT')
GOOGLE_SAFE_BROWSING_KEY = os.getenv('GOOGLE_SAFE_BROWSING_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

# ============ APP VERSION ============
APP_VERSION = os.getenv('APP_VERSION', '1.0.0')
BUILD_NUMBER = os.getenv('BUILD_NUMBER', '1')