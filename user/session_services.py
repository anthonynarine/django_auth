"""Services for creating and revoking authenticated sessions."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import exceptions

from .models import AuthSession, UserToken
from .security_utils import get_client_ip
from .session_selectors import get_active_session


def _session_expires_at():
    return timezone.now() + timedelta(days=settings.AUTH_SESSION_LIFETIME_DAYS)


def _request_metadata(request) -> tuple[str | None, str]:
    client_ip = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:2048] if request else ""
    return client_ip, user_agent


def create_session(
    user,
    *,
    request=None,
    authentication_method: str = "password",
    authentication_strength: str = "password",
):
    """Create a server-controlled authenticated session."""
    now = timezone.now()
    client_ip, user_agent = _request_metadata(request)
    return AuthSession.objects.create(
        user=user,
        expires_at=_session_expires_at(),
        last_seen_at=now,
        recent_auth_at=now,
        authentication_method=authentication_method,
        authentication_strength=authentication_strength,
        created_ip=client_ip,
        last_ip=client_ip,
        user_agent=user_agent,
    )


def touch_session(session: AuthSession, *, request=None, authentication_strength: str | None = None):
    """Update session recency metadata without making request-auth depend on it."""
    now = timezone.now()
    client_ip, user_agent = _request_metadata(request)
    update_fields = ["last_seen_at", "last_ip", "user_agent"]
    session.last_seen_at = now
    session.last_ip = client_ip
    session.user_agent = user_agent
    if authentication_strength:
        session.authentication_strength = authentication_strength
        session.recent_auth_at = now
        update_fields.extend(["authentication_strength", "recent_auth_at"])
    session.save(update_fields=update_fields)
    return session


def _get_cached_request_session(request, sid: str):
    cached_sid = getattr(request, "_auth_session_sid", None)
    cached_session = getattr(request, "_auth_session", None)
    if cached_sid == sid and cached_session is not None:
        return cached_session
    return None


def _cache_request_session(request, session: AuthSession):
    setattr(request, "_auth_session_sid", str(session.id))
    setattr(request, "_auth_session", session)


def validate_access_session(payload: dict, *, user=None, request=None):
    """Validate the sid claim for an access token when present."""
    sid = payload.get("sid")
    enforcement = getattr(settings, "AUTH_SESSION_ENFORCEMENT", "OBSERVE").upper()
    if not sid:
        if enforcement == "ENFORCE":
            raise exceptions.AuthenticationFailed("Session required.", code=401)
        return None

    if request is not None:
        cached_session = _get_cached_request_session(request, str(sid))
        if cached_session is not None:
            if user is not None and cached_session.user_id != user.id:
                raise exceptions.AuthenticationFailed("unauthenticated", code=401)
            return cached_session

    session = get_active_session(sid, user_id=payload.get("user_id"))
    if not session:
        raise exceptions.AuthenticationFailed("unauthenticated", code=401)

    if user is not None and session.user_id != user.id:
        raise exceptions.AuthenticationFailed("unauthenticated", code=401)

    if request is not None:
        _cache_request_session(request, session)

    return session


def revoke_session(session: AuthSession, *, reason: str) -> int:
    """Revoke one authenticated session and its refresh tokens."""
    if not session:
        return 0

    now = timezone.now()
    updated = AuthSession.objects.filter(
        id=session.id,
        revoked_at__isnull=True,
    ).update(
        revoked_at=now,
        revocation_reason=reason,
        last_seen_at=now,
    )
    UserToken.objects.filter(
        auth_session=session,
        revoked_at__isnull=True,
    ).update(
        is_revoked=True,
        revoked_at=now,
        revocation_reason=reason,
    )
    return updated


def revoke_all_sessions(user, *, reason: str) -> int:
    """Revoke every authenticated session for one user."""
    now = timezone.now()
    session_ids = list(
        AuthSession.objects.filter(user=user, revoked_at__isnull=True).values_list("id", flat=True)
    )
    if session_ids:
        AuthSession.objects.filter(id__in=session_ids).update(
            revoked_at=now,
            revocation_reason=reason,
            last_seen_at=now,
        )

    UserToken.objects.filter(
        user=user,
        revoked_at__isnull=True,
    ).update(
        is_revoked=True,
        revoked_at=now,
        revocation_reason=reason,
    )
    return len(session_ids)


@transaction.atomic
def get_session_or_create_for_refresh(record: UserToken, *, request=None):
    """Return the session for a refresh token, migrating legacy rows when needed."""
    if record.auth_session_id:
        session = AuthSession.objects.select_for_update().filter(id=record.auth_session_id).first()
        if session and session.revoked_at is None and session.expires_at > timezone.now() and session.user.is_active:
            return session
        raise exceptions.AuthenticationFailed("unauthenticated", code=401)

    session = create_session(
        record.user,
        request=request,
        authentication_method="refresh",
        authentication_strength="password",
    )
    record.auth_session = session
    record.save(update_fields=["auth_session"])
    return session
