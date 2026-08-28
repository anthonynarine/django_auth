# Filename: authentication/test_settings.py
"""Settings used only for local automated tests."""

from .settings import *  # noqa: F403


# Step 1: Keep tests independent from a developer's local PostgreSQL service.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "test.sqlite3",  # noqa: F405
    }
}

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]
