"""Shared security helpers for token and session management."""

from __future__ import annotations


def get_client_ip(request) -> str | None:
    """Return a best-effort client IP address from a Django request."""
    if request is None:
        return None

    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or None

    return request.META.get("REMOTE_ADDR")
