# Filename: authentication/postgres_test_settings.py
"""PostgreSQL settings for tests that require real transaction semantics."""

from decouple import config

from .settings import *  # noqa: F403


# Step 1: Keep PostgreSQL-only security tests explicit and opt-in.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_TEST_DB_NAME", default="auth_test_db"),
        "USER": config("POSTGRES_TEST_DB_USER", default="auth_test_user"),
        "PASSWORD": config("POSTGRES_TEST_DB_PASSWORD"),
        "HOST": config("POSTGRES_TEST_DB_HOST", default="localhost"),
        "PORT": config("POSTGRES_TEST_DB_PORT", default=5432, cast=int),
        "TEST": {
            "NAME": config(
                "POSTGRES_TEST_DATABASE_NAME",
                default="test_auth_test_db",
            ),
        },
    }
}

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]
TESTING = True
