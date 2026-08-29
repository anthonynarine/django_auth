"""Read helpers for authenticated session state."""

from __future__ import annotations

from django.utils import timezone

from .models import AuthSession


def get_active_session(session_id, *, user_id=None):
    """Return an active session when it exists and has not expired."""
    if not session_id:
        return None

    queryset = AuthSession.objects.select_related("user")
    if user_id is not None:
        queryset = queryset.filter(user_id=user_id)

    session = queryset.filter(
        id=session_id,
        revoked_at__isnull=True,
        expires_at__gt=timezone.now(),
    ).first()
    if not session:
        return None

    if not session.user.is_active:
        return None

    return session
