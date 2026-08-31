"""Write helpers for security events."""

from __future__ import annotations

import logging

from django.db import transaction

from security.models import SecurityEvent
from security.utils import (
    get_client_ip,
    safe_request_method,
    safe_request_path,
    safe_user_agent,
    sanitize_security_metadata,
)

logger = logging.getLogger(__name__)


def _default_outcome(event_type: str) -> str:
    mapping = {
        SecurityEvent.EventType.LOGIN_SUCCESS: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.MFA_SUCCESS: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.MFA_ENABLED: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.SESSION_CREATED: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.TOKEN_REFRESHED: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.PASSWORD_CHANGE_SUCCESS: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.REAUTH_SUCCESS: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.PASSWORD_RESET_REQUESTED: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.PASSWORD_RESET_COMPLETED: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.LOGIN_FAILURE: SecurityEvent.Outcome.FAILURE,
        SecurityEvent.EventType.MFA_FAILURE: SecurityEvent.Outcome.FAILURE,
        SecurityEvent.EventType.MFA_CHANGE_DENIED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE: SecurityEvent.Outcome.FAILURE,
        SecurityEvent.EventType.PASSWORD_CHANGE_THROTTLED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.PASSWORD_CHANGE_BLOCKED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.REAUTH_FAILURE: SecurityEvent.Outcome.FAILURE,
        SecurityEvent.EventType.SESSION_ACCESS_DENIED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.INACTIVE_USER_DENIED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.SESSION_REVOKED: SecurityEvent.Outcome.REVOKED,
        SecurityEvent.EventType.LOGOUT: SecurityEvent.Outcome.REVOKED,
        SecurityEvent.EventType.LOGOUT_ALL: SecurityEvent.Outcome.REVOKED,
        SecurityEvent.EventType.REFRESH_REPLAY_DETECTED: SecurityEvent.Outcome.REVOKED,
        SecurityEvent.EventType.MFA_DISABLED: SecurityEvent.Outcome.REVOKED,
        SecurityEvent.EventType.ACCOUNT_DISABLED: SecurityEvent.Outcome.REVOKED,
        SecurityEvent.EventType.LOGIN_THROTTLED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.LOGIN_BLOCKED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.OTP_THROTTLED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.OTP_BLOCKED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.PASSWORD_RESET_THROTTLED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.PASSWORD_RESET_BLOCKED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.REAUTH_THROTTLED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.REAUTH_BLOCKED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.MFA_CHANGE_THROTTLED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.MFA_CHANGE_BLOCKED: SecurityEvent.Outcome.DENIED,
    }
    return mapping.get(event_type, SecurityEvent.Outcome.SUCCESS)


def _default_severity(event_type: str) -> str:
    mapping = {
        SecurityEvent.EventType.LOGIN_SUCCESS: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.MFA_SUCCESS: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.MFA_ENABLED: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.SESSION_CREATED: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.TOKEN_REFRESHED: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.PASSWORD_CHANGE_SUCCESS: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.REAUTH_SUCCESS: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.PASSWORD_RESET_REQUESTED: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.PASSWORD_RESET_COMPLETED: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.LOGIN_FAILURE: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.MFA_FAILURE: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.MFA_CHANGE_DENIED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.PASSWORD_CHANGE_THROTTLED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.PASSWORD_CHANGE_BLOCKED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.REAUTH_FAILURE: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.SESSION_ACCESS_DENIED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.INACTIVE_USER_DENIED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.SESSION_REVOKED: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.LOGOUT: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.LOGOUT_ALL: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.REFRESH_REPLAY_DETECTED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.MFA_DISABLED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.ACCOUNT_DISABLED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.LOGIN_THROTTLED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.LOGIN_BLOCKED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.OTP_THROTTLED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.OTP_BLOCKED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.PASSWORD_RESET_THROTTLED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.PASSWORD_RESET_BLOCKED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.REAUTH_THROTTLED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.REAUTH_BLOCKED: SecurityEvent.Severity.HIGH,
        SecurityEvent.EventType.MFA_CHANGE_THROTTLED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.MFA_CHANGE_BLOCKED: SecurityEvent.Severity.HIGH,
    }
    return mapping.get(event_type, SecurityEvent.Severity.INFO)


def record_security_event(
    event_type: str,
    *,
    request=None,
    user=None,
    auth_session=None,
    outcome: str | None = None,
    severity: str | None = None,
    reason_code: str = "",
    metadata: dict | None = None,
):
    """Persist a durable security event without affecting auth flow."""

    sanitized_metadata = sanitize_security_metadata(metadata or {})
    payload = {
        "event_type": event_type,
        "outcome": outcome or _default_outcome(event_type),
        "severity": severity or _default_severity(event_type),
        "user": user,
        "auth_session": auth_session,
        "ip_address": get_client_ip(request),
        "user_agent": safe_user_agent(request),
        "request_method": safe_request_method(request),
        "request_path": safe_request_path(request),
        "reason_code": reason_code,
        "metadata": sanitized_metadata,
    }

    def _create():
        try:
            SecurityEvent.objects.create(**payload)
        except Exception:
            logger.exception("Failed to persist security event %s", event_type)

    transaction.on_commit(_create)

