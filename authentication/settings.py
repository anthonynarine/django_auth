import os
import sys
from pathlib import Path
from decouple import config
from django.conf import settings
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

def csv_config(name):
    return [
        item.strip()
        for item in config(name, default="").split(",")
        if item.strip()
    ]

ALLOWED_HOSTS = [
    'ant-django-auth-62cf01255868.herokuapp.com',
    'localhost', '127.0.0.1',
    "localhost:3000",
    *csv_config("ALLOWED_HOSTS_EXTRA"),
]

# Decide which React app base URL to use based on DEBUG
REACT_APP_BASE_URL = config(
    'REACT_APP_BASE_URL_DEV') if DEBUG else config('REACT_APP_BASE_URL_PROD'
)


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
    "abuse",
    "security",
    "user",
    "mail"
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    'corsheaders.middleware.CorsMiddleware',
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # 2nd custom middleware: Disable CSRF
    "authentication.custom_middleware.disable_csrf.DisableCSRFMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # 1st custom middleware: Token Authentication
    "authentication.custom_middleware.token_auth.TokenAuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # 3rd custom middleware: JWT Refresh
    # "authentication.custom_middleware.jwt_refresh.TokenRefreshMiddleware",
    # 4th custom middleware: Cookie Settings
    # "authentication.custom_middleware.cookie_settings.CookieSettingsMiddleware"
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
    "http://localhost:5173", 
    "https://ant-django-auth-62cf01255868.herokuapp.com",
    "https://gaitobservatory.com",
    'https://gait.netlify.app',
    # Additional origins...
    *csv_config("CORS_ALLOWED_ORIGINS_EXTRA"),
]
CORS_ALLOW_CREDENTIALS = True
CORS_EXPOSE_HEADERS = ["X-CSRFToken", "Retry-After"]

CSRF_TRUSTED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:3001',
    "http://localhost:5173",
    "https://ant-django-auth-62cf01255868.herokuapp.com",
    "https://gaitobservatory.com",
    'https://gait.netlify.app',
    # Additional trusted origins...
    *csv_config("CSRF_TRUSTED_ORIGINS_EXTRA"),
]


# JWT Secretes
JWT_REFRESH_SECRET = config('JWT_REFRESH_SECRET')
JWT_ACCESS_SECRET = config('JWT_ACCESS_SECRET', default='')
JWT_REFRESH_ROTATION_ENABLED = config(
    'JWT_REFRESH_ROTATION_ENABLED',
    default=True,
    cast=bool,
)
AUTH_SESSION_ENFORCEMENT = config(
    "AUTH_SESSION_ENFORCEMENT",
    default="OBSERVE",
).upper()
AUTH_SESSION_LIFETIME_DAYS = config(
    "AUTH_SESSION_LIFETIME_DAYS",
    default=7,
    cast=int,
)
RECENT_AUTH_MAX_AGE_SECONDS = config(
    "RECENT_AUTH_MAX_AGE_SECONDS",
    default=600,
    cast=int,
)

ABUSE_CONTROL_ENFORCEMENT = config("ABUSE_CONTROL_ENFORCEMENT", default="ENFORCE").upper()


def abuse_policy(*, window_seconds: int, throttle_threshold: int, block_threshold: int, block_seconds: int):
    return {
        "window_seconds": window_seconds,
        "throttle_threshold": throttle_threshold,
        "block_threshold": block_threshold,
        "block_seconds": block_seconds,
    }


ABUSE_CONTROL_POLICIES = {
    "LOGIN_IP": abuse_policy(
        window_seconds=config("ABUSE_LOGIN_IP_WINDOW_SECONDS", default=60, cast=int),
        throttle_threshold=config("ABUSE_LOGIN_IP_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_LOGIN_IP_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_LOGIN_IP_BLOCK_SECONDS", default=900, cast=int),
    ),
    "LOGIN_ACCOUNT": abuse_policy(
        window_seconds=config("ABUSE_LOGIN_ACCOUNT_WINDOW_SECONDS", default=60, cast=int),
        throttle_threshold=config("ABUSE_LOGIN_ACCOUNT_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_LOGIN_ACCOUNT_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_LOGIN_ACCOUNT_BLOCK_SECONDS", default=900, cast=int),
    ),
    "LOGIN_IP_ACCOUNT": abuse_policy(
        window_seconds=config("ABUSE_LOGIN_IP_ACCOUNT_WINDOW_SECONDS", default=60, cast=int),
        throttle_threshold=config("ABUSE_LOGIN_IP_ACCOUNT_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_LOGIN_IP_ACCOUNT_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_LOGIN_IP_ACCOUNT_BLOCK_SECONDS", default=900, cast=int),
    ),
    "OTP_SESSION": abuse_policy(
        window_seconds=config("ABUSE_OTP_SESSION_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_OTP_SESSION_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_OTP_SESSION_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_OTP_SESSION_BLOCK_SECONDS", default=900, cast=int),
    ),
    "OTP_ACCOUNT": abuse_policy(
        window_seconds=config("ABUSE_OTP_ACCOUNT_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_OTP_ACCOUNT_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_OTP_ACCOUNT_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_OTP_ACCOUNT_BLOCK_SECONDS", default=900, cast=int),
    ),
    "OTP_IP": abuse_policy(
        window_seconds=config("ABUSE_OTP_IP_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_OTP_IP_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_OTP_IP_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_OTP_IP_BLOCK_SECONDS", default=900, cast=int),
    ),
    "PASSWORD_RESET_IP": abuse_policy(
        window_seconds=config("ABUSE_PASSWORD_RESET_IP_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_PASSWORD_RESET_IP_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_PASSWORD_RESET_IP_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_PASSWORD_RESET_IP_BLOCK_SECONDS", default=900, cast=int),
    ),
    "PASSWORD_RESET_ACCOUNT": abuse_policy(
        window_seconds=config("ABUSE_PASSWORD_RESET_ACCOUNT_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_PASSWORD_RESET_ACCOUNT_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_PASSWORD_RESET_ACCOUNT_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_PASSWORD_RESET_ACCOUNT_BLOCK_SECONDS", default=900, cast=int),
    ),
    "REAUTH_SESSION": abuse_policy(
        window_seconds=config("ABUSE_REAUTH_SESSION_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_REAUTH_SESSION_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_REAUTH_SESSION_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_REAUTH_SESSION_BLOCK_SECONDS", default=900, cast=int),
    ),
    "REAUTH_ACCOUNT": abuse_policy(
        window_seconds=config("ABUSE_REAUTH_ACCOUNT_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_REAUTH_ACCOUNT_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_REAUTH_ACCOUNT_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_REAUTH_ACCOUNT_BLOCK_SECONDS", default=900, cast=int),
    ),
    "PASSWORD_CHANGE_SESSION": abuse_policy(
        window_seconds=config("ABUSE_PASSWORD_CHANGE_SESSION_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_PASSWORD_CHANGE_SESSION_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_PASSWORD_CHANGE_SESSION_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_PASSWORD_CHANGE_SESSION_BLOCK_SECONDS", default=900, cast=int),
    ),
    "PASSWORD_CHANGE_ACCOUNT": abuse_policy(
        window_seconds=config("ABUSE_PASSWORD_CHANGE_ACCOUNT_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_PASSWORD_CHANGE_ACCOUNT_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_PASSWORD_CHANGE_ACCOUNT_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_PASSWORD_CHANGE_ACCOUNT_BLOCK_SECONDS", default=900, cast=int),
    ),
    "MFA_CHANGE_SESSION": abuse_policy(
        window_seconds=config("ABUSE_MFA_CHANGE_SESSION_WINDOW_SECONDS", default=300, cast=int),
        throttle_threshold=config("ABUSE_MFA_CHANGE_SESSION_THROTTLE_THRESHOLD", default=5, cast=int),
        block_threshold=config("ABUSE_MFA_CHANGE_SESSION_BLOCK_THRESHOLD", default=10, cast=int),
        block_seconds=config("ABUSE_MFA_CHANGE_SESSION_BLOCK_SECONDS", default=900, cast=int),
    ),
}

if AUTH_SESSION_ENFORCEMENT not in {"OFF", "OBSERVE", "ENFORCE"}:
    print("AUTH_SESSION_ENFORCEMENT must be OFF, OBSERVE, or ENFORCE.")
    sys.exit(1)

if not JWT_ACCESS_SECRET or not JWT_REFRESH_SECRET:
    print('JWT secrets are not set. Application is shutting down.')
    sys.exit(1)


# Email Settings (Zoho Mail via SMTP in production; console email in local dev)
if DEBUG:
    DEFAULT_FROM_EMAIL = config(
        "DEFAULT_FROM_EMAIL",
        default="accounts@gaitobservatory.local",
    )
    SERVER_EMAIL = config("SERVER_EMAIL", default=DEFAULT_FROM_EMAIL)
    EMAIL_BACKEND = config(
        "EMAIL_BACKEND",
        default="django.core.mail.backends.console.EmailBackend",
    )
    EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="")
    EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="")
else:
    DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL")
    SERVER_EMAIL = config("SERVER_EMAIL", default=DEFAULT_FROM_EMAIL)
    EMAIL_BACKEND = config(
        "EMAIL_BACKEND",
        default="django.core.mail.backends.smtp.EmailBackend",
    )
    EMAIL_HOST_USER = config("EMAIL_HOST_USER")
    EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")

EMAIL_HOST = config("EMAIL_HOST", default="smtp.zoho.com")
EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
# Zoho requires an app-specific password here (not the account login
# password) when 2FA is enabled on the mailbox.

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

# Password reset links are single-use (the Reset row is deleted after use),
# but must also expire on their own -- see check_token() in
# ResetPasswordRequestView (user/views.py), which enforces this timeout.
PASSWORD_RESET_TIMEOUT = 3600  # 1 hour

REST_FRAMEWORK = {
    # ScopedRateThrottle is a no-op for any view without a `throttle_scope`
    # attribute, so enabling it globally doesn't affect unrelated views.
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.ScopedRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'login': '5/min',
        'otp_verify': '5/min',
        'password_reset': '5/min',
        'contact': '5/min',
    },
}

if settings.DEBUG:
    # Development settings
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = "Lax"
    CSRF_COOKIE_SAMESITE = "Lax"
    # SESSION_COOKIE_DOMAIN = "localhost"
    # CSRF_COOKIE_DOMAIN = "localhost"
else:
    #Production settings
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "None"
    CSRF_COOKIE_SAMESITE = "None"
    # SESSION_COOKIE_DOMAIN = ".ant-django-auth-62cf01255868.herokuapp.com"
    # CSRF_COOKIE_DOMAIN = ".ant-django-auth-62cf01255868.herokuapp.com"


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
