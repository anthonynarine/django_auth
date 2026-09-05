"""Read helpers for security audit data."""

from __future__ import annotations

from datetime import timedelta

from django.utils import timezone

from security.models import SecurityEvent
from security.presentation import get_category_labels, get_severity_labels
from user.models import AuthSession


def _apply_temporal_filters(queryset, *, created_from=None, created_to=None):
    if created_from:
        queryset = queryset.filter(created_at__gte=created_from)
    if created_to:
        queryset = queryset.filter(created_at__lte=created_to)
    return queryset.order_by("-created_at", "-id")


def list_security_events(*, event_type=None, outcome=None, severity=None, user=None, session=None,
                         created_from=None, created_to=None):
    queryset = SecurityEvent.objects.select_related("user", "auth_session")
    if event_type:
        queryset = queryset.filter(event_type=event_type)
    if outcome:
        queryset = queryset.filter(outcome=outcome)
    if severity:
        queryset = queryset.filter(severity=severity)
    if user:
        if str(user).isdigit():
            queryset = queryset.filter(user_id=int(user))
        else:
            queryset = queryset.filter(user__email=user)
    if session:
        queryset = queryset.filter(auth_session_id=session)
    return _apply_temporal_filters(queryset, created_from=created_from, created_to=created_to)


def list_security_sessions(*, user=None, active=None, revoked=None, created_from=None, created_to=None):
    queryset = AuthSession.objects.select_related("user")
    if user:
        if str(user).isdigit():
            queryset = queryset.filter(user_id=int(user))
        else:
            queryset = queryset.filter(user__email=user)
    if active is True:
        queryset = queryset.filter(revoked_at__isnull=True, expires_at__gt=timezone.now())
    elif active is False:
        queryset = queryset.exclude(revoked_at__isnull=True, expires_at__gt=timezone.now())
    if revoked is True:
        queryset = queryset.filter(revoked_at__isnull=False)
    elif revoked is False:
        queryset = queryset.filter(revoked_at__isnull=True)
    if created_from:
        queryset = queryset.filter(created_at__gte=created_from)
    if created_to:
        queryset = queryset.filter(created_at__lte=created_to)
    return queryset


def get_security_summary(*, window=None):
    window = window or timedelta(hours=24)
    since = timezone.now() - window
    events = SecurityEvent.objects.filter(created_at__gte=since)

    return {
        "window_hours": int(window.total_seconds() // 3600),
        "category_labels": get_category_labels(),
        "severity_labels": get_severity_labels(),
        "successful_logins": events.filter(event_type=SecurityEvent.EventType.LOGIN_SUCCESS).count(),
        "failed_logins": events.filter(event_type=SecurityEvent.EventType.LOGIN_FAILURE).count(),
        "replay_events": events.filter(
            event_type=SecurityEvent.EventType.REFRESH_REPLAY_DETECTED
        ).count(),
        "sessions_revoked": events.filter(
            event_type__in=[
                SecurityEvent.EventType.SESSION_REVOKED,
                SecurityEvent.EventType.LOGOUT,
                SecurityEvent.EventType.LOGOUT_ALL,
                SecurityEvent.EventType.REFRESH_REPLAY_DETECTED,
            ]
        ).count(),
        "active_sessions": AuthSession.objects.filter(
            revoked_at__isnull=True,
            expires_at__gt=timezone.now(),
            user__is_active=True,
        ).count(),
    }
