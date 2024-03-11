
from pathlib import Path
from decouple import config
import os, sys
import django_heroku
import dj_database_url


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)


ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # 3rd party
    "rest_framework",
    'corsheaders',
    # local
    "user", 
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    'corsheaders.middleware.CorsMiddleware',
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "authentication.urls"


#Updated
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',  # Include this for admin sidebar
                'django.contrib.auth.context_processors.auth',  # Include this for authentication
                'django.contrib.messages.context_processors.messages',  # Include this for messages
                # Add any other context processors you might be using
            ],
        },
    },
]

WSGI_APPLICATION = "authentication.wsgi.application"


# ADD
# DATABASES = {
#     'default': {
        
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': config('POSTGRESQL_DB_NAME'),
#         'USER': config('POSTGRESQL_DB_USER'),
#         'PASSWORD': config('POSTGRESQL_DB_PASSWORD'),
#         'HOST': config('POSTGRESQL_DB_HOST', default='localhost'),
#         'PORT': config('POSTGRESQL_DB_PORT', default=5432, cast=int),
#     }
# }

DATABASES = {
    'default': dj_database_url.config(default=os.environ.get('DATABASE_URL'))
}


AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


LANGUAGE_CODE = "en-us"

#..UPDATED...
TIME_ZONE = 'America/New_York'  # Set your desired timezone

USE_I18N = True

USE_TZ = True



STATIC_URL = '/static/'

#add
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'



DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"



#ADD
AUTH_USER_MODEL = "user.CustomUser"

#ADD.
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # Add the domains allowed to make requests here
    "http://localhost:3001",  # Add the domains allowed to make requests here
    # Add more origins as needed
]

#Add
CORS_ALLOW_CREDENTIALS = True  # Allows cookies

#Add
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'localhost'
EMAIL_PORT = 1025
EMAIL_USE_TLS = False

#Add
DEFAULT_FROM_EMAIL = 'noreply@yourdomain.com'



#Add
# Get the JWT secrets using config
JWT_ACCESS_SECRET = config('JWT_ACCESS_SECRET')
JWT_REFRESH_SECRET = config('JWT_REFRESH_SECRET')

#Add
# Check if the JWT secrets are set
if not JWT_ACCESS_SECRET or not JWT_REFRESH_SECRET:
    print('JWT secrets are not set. Application is shutting down.')
    sys.exit(1)  # Exit the application with an error code


#ADD
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


django_heroku.settings(locals())