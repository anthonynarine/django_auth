"""Shared helpers for audit-safe request context and metadata."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime
from uuid import UUID


_SENSITIVE_KEY_PARTS = (
    "password",
    "passphrase",
    "token",
    "refresh",
    "access",
    "authorization",
    "otp",
    "mfa",
    "secret",
    "reset",
    "jwt",
    "cookie",
    "private_key",
    "api_key",
)


def get_client_ip(request) -> str | None:
    """Return a best-effort client IP from trusted proxy headers."""
    if request is None:
        return None

    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        for candidate in forwarded_for.split(","):
            candidate = candidate.strip()
            if candidate:
                return candidate

    remote_addr = request.META.get("REMOTE_ADDR")
    return remote_addr or None


def _truncate_text(value: str, limit: int = 512) -> str:
    return value[:limit]


def _sanitize_scalar(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return _truncate_text(str(value))


def sanitize_security_metadata(value, *, _depth: int = 0):
    """Recursively remove obvious secrets from audit metadata."""
    if _depth > 5:
        return "[TRUNCATED]"

    if isinstance(value, Mapping):
        sanitized = {}
        for key, child in value.items():
            key_text = str(key)
            if any(part in key_text.lower() for part in _SENSITIVE_KEY_PARTS):
                sanitized[key_text] = "[REDACTED]"
            else:
                sanitized[key_text] = sanitize_security_metadata(child, _depth=_depth + 1)
        return sanitized

    if isinstance(value, (list, tuple, set)):
        return [sanitize_security_metadata(item, _depth=_depth + 1) for item in list(value)[:25]]

    return _sanitize_scalar(value)


def safe_request_path(request) -> str:
    if request is None:
        return ""
    return _truncate_text(getattr(request, "path", "") or "")


def safe_request_method(request) -> str:
    if request is None:
        return ""
    return _truncate_text(getattr(request, "method", "") or "")


def safe_user_agent(request) -> str:
    if request is None:
        return ""
    user_agent = request.META.get("HTTP_USER_AGENT", "") if hasattr(request, "META") else ""
    return _truncate_text(user_agent, 2048)


def humanize_code(value: str) -> str:
    """Convert an enum/code string into a human-readable label."""
    if not value:
        return ""
    return str(value).replace("_", " ").strip().title()

