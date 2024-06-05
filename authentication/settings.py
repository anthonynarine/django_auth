import os
import sys
from pathlib import Path
from decouple import config
import django_heroku
import dj_database_url
from .logging_conf import julia_fiesta_logs

# Setup logging configurations
julia_fiesta_logs()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = [
    'ant-django-auth-62cf01255868.herokuapp.com',
    'localhost', '127.0.0.1',
    "localhost:3000"]

# Decide which React app base URL to use based on DEBUG
REACT_APP_BASE_URL = config('REACT_APP_BASE_URL_DEV') if DEBUG else config('REACT_APP_BASE_URL_PROD')


# Application definition

INSTALLED_APPS = [
    # Django default apps
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    
    # Third-party apps
    "rest_framework",
    'corsheaders',
    
    # Your apps
    "user",
    "mail"
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    'corsheaders.middleware.CorsMiddleware',
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # 1st custom middleware!!!
    "authentication.custom_middleware.token_auth.TokenAuthenticationMiddleware", 
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # 2nd custom middleware!!! im a madman
    "authentication.custom_middleware.disable_csrf.DisableCSRFMiddleware",
    # 3rd custom middleware!! this is getting crazy
    "authentication.custom_middleware.cookie_settings.CookieSettingsMiddleware",
]

# URL and WSGI Configuration

ROOT_URLCONF = "authentication.urls"
WSGI_APPLICATION = "authentication.wsgi.application"

# Templates

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


# Database Configuration

if os.environ.get("DATABASE_URL"):
    DATABASES = {
        'default': dj_database_url.config(default='sqlite:///db.sqlite3', conn_max_age=600)
    }
else: 
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': config('POSTGRESQL_DB_NAME'),
            'USER': config('POSTGRESQL_DB_USER'),
            'PASSWORD': config('POSTGRESQL_DB_PASSWORD'),
            'HOST': config('POSTGRESQL_DB_HOST', default='localhost'),
            'PORT': config('POSTGRESQL_DB_PORT', default=5432, cast=int),
        }
    }

# Static files configuration
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'


# Internationalization and Time Zone
LANGUAGE_CODE = "en-us"
TIME_ZONE = 'America/New_York'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Authentication and Users
AUTH_USER_MODEL = "user.CustomUser"
AUTH_PASSWORD_VALIDATORS = [
    # Password validators...
]


# CORS Headers Configuration
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001",
    "https://ant-django-auth-62cf01255868.herokuapp.com",
    # Additional origins...
]
CORS_ALLOW_CREDENTIALS = True

CSRF_TRUSTED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:3001',
    # Additional trusted origins...
]


# JWT Secretes
JWT_REFRESH_SECRET = config('JWT_REFRESH_SECRET')
JWT_ACCESS_SECRET = config('JWT_ACCESS_SECRET', default='')

if not JWT_ACCESS_SECRET or not JWT_REFRESH_SECRET:
    print('JWT secrets are not set. Application is shutting down.')
    sys.exit(1)


# Email Settings
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL")
EMAIL_BACKEND = 'sendgrid_backend.SendgridBackend'
SENDGRID_API_KEY = config("SENDGRID_API_KEY")

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
        'OPTIONS': {
            'user_attributes': ('username', 'email', 'first_name', 'last_name'),
            'max_similarity': 0.7,
        },
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        },
    },
    # TODO  impliment a way to add common pw  validators. 
    
    # {
    #     'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    #     'OPTIONS': {
    #         'password_list_path': 'D:/react-django/django_auth/auth_venv/Lib/site-packages/django/contrib/auth/common-passwords.txt.gz',
    #     },
    # },
    # {
    #     'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    # },
]

# CSRF_COOKIE_SECURE = not DEBUG
# # Ensures the CSRF cookie is only sent over HTTPS in production

# SESSION_COOKIE_SECURE = not DEBUG
# Ensures the session cookie is only sent over HTTPS in production

# CSRF_COOKIE_SAMESITE = "None"
# # Allows the CSRF cookie to be sent in cross-site requests

# SESSION_COOKIE_SAMESITE = "None"
# # Allows the session cookie to be sent in cross-site request

# CSRF_COOKIE_HTTPONLY = False  
# # Ensures the CSRF cookie is accessible to JavaScript for inclusion in AJAX requests

# SECURE_SSL_REDIRECT = not DEBUG
# # Redirects all HTTP requests to HTTPS in production

# SECURE_BROWSER_XSS_FILTER = True
# Enables browser's built-in XSS (Cross-Site Scripting) protection and blocks rendering if an XSS attack is detected. 

# X_FRAME_OPTIONS = 'DENY'
# Ensures that your application cannot be embedded in a frame, protecting users from deceptive UI tricks.

# Dynamic SameSite attribute based on enviroment
if DEBUG:
    ACCESS_TOKEN_SAMESITE = "None"
    REFRESH_TOKEN_SAMESITE = "None"
else:
    ACCESS_TOKEN_SAMESITE = "Strict"
    REFRESH_TOKEN_SAMESITE = "Strict"
    
    # Allows the CSRF

# Heroku Deployment Integration
django_heroku.settings(locals())
