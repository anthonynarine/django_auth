import os
import sys
from pathlib import Path
from decouple import config
import django_heroku
import dj_database_url

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=True, cast=bool)
ALLOWED_HOSTS = ['ant-django-auth-62cf01255868.herokuapp.com', 'localhost', '127.0.0.1', "localhost:3000"]
# Decide which React app base URL to use based on DEBUG
REACT_APP_BASE_URL = config('REACT_APP_BASE_URL_DEV') if DEBUG else config('REACT_APP_BASE_URL_PROD')
JWT_ACCESS_SECRET = config('JWT_ACCESS_SECRET', default='')

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
    "user.middleware.TokenAuthenticationMiddleware", 
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
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
    # Additional origins...
]
CORS_ALLOW_CREDENTIALS = True

CSRF_TRUSTED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:3001',
    # Additional trusted origins...
]


# JWT Secretes
JWT_ACCESS_SECRET = config('JWT_ACCESS_SECRET')
JWT_REFRESH_SECRET = config('JWT_REFRESH_SECRET')

if not JWT_ACCESS_SECRET or not JWT_REFRESH_SECRET:
    print('JWT secrets are not set. Application is shutting down.')
    sys.exit(1)

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'debug.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

# Email Settings
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL")

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
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
        'OPTIONS': {
            'password_list_path': 'django/contrib/auth/common-passwords.txt.gz',
        },
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Heroku Deployment Integration
django_heroku.settings(locals())
