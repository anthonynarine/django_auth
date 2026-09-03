"""Account-security helpers for sensitive credential and MFA operations."""

from __future__ import annotations

from datetime import timedelta

import pyotp
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework import exceptions
from rest_framework.exceptions import ValidationError as DRFValidationError

from abuse.services import (
    check as abuse_check,
    record_failure as abuse_record_failure,
    record_success as abuse_record_success,
)
from security.models import SecurityEvent
from security.services import record_security_event

from .models import AuthSession, UserToken
from .session_services import (
    revoke_other_sessions,
    touch_session,
)
from .step_up import (
    STEP_UP_POLICIES,
    StepUpRequirement,
    require_step_up,
)


def get_recent_auth_max_age_seconds() -> int:
    return getattr(settings, "RECENT_AUTH_MAX_AGE_SECONDS", 600)


def resolve_current_auth_session(request):
    """Return the session bound to the request, or the newest active session for the user."""
    session = getattr(request, "auth_session", None)
    user = getattr(request, "user", None)
    if session is not None and user is not None and getattr(user, "id", None) == session.user_id:
        return session
    if user is not None and getattr(user, "is_authenticated", False):
        return (
            user.auth_sessions.filter(revoked_at__isnull=True)
            .order_by("-last_seen_at", "-created_at")
            .first()
        )
    return None


def is_recent_auth(session, *, max_age_seconds: int | None = None) -> bool:
    if session is None or session.recent_auth_at is None:
        return False
    max_age = max_age_seconds if max_age_seconds is not None else get_recent_auth_max_age_seconds()
    return session.recent_auth_at >= timezone.now() - timedelta(seconds=max_age)


def require_recent_auth(
    session,
    *,
    request=None,
    user=None,
    operation: str,
    failure_event: str,
    failure_reason: str = "RECENT_AUTH_REQUIRED",
):
    requirement = StepUpRequirement(
        minimum_strength="password",
        max_auth_age_seconds=get_recent_auth_max_age_seconds(),
    )
    return require_step_up(
        session,
        requirement,
        request=request,
        user=user,
        operation=operation,
        failure_event=failure_event,
    )


def reauthenticate_session(
    *,
    user,
    session,
    current_password: str,
    otp: str | None = None,
    request=None,
):
    if session is None:
        record_security_event(
            SecurityEvent.EventType.REAUTH_FAILURE,
            outcome=SecurityEvent.Outcome.FAILURE,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="SESSION_REQUIRED",
            user=user,
            request=request,
        )
        raise DRFValidationError({"detail": "Active session required."})

    decision = abuse_check("REAUTH_SESSION", request=request, user=user, auth_session=session, account=user.email)
    if not decision.allowed:
        raise exceptions.Throttled(wait=decision.retry_after_seconds)

    decision = abuse_check("REAUTH_ACCOUNT", request=request, user=user, account=user.email)
    if not decision.allowed:
        raise exceptions.Throttled(wait=decision.retry_after_seconds)

    if not user.check_password(current_password):
        abuse_record_failure("REAUTH_SESSION", request=request, user=user, auth_session=session, account=user.email)
        abuse_record_failure("REAUTH_ACCOUNT", request=request, user=user, account=user.email)
        record_security_event(
            SecurityEvent.EventType.STEP_UP_FAILURE,
            outcome=SecurityEvent.Outcome.FAILURE,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="CURRENT_PASSWORD_INVALID",
            user=user,
            auth_session=session,
            request=request,
            metadata={"authentication_method": "password"},
        )
        record_security_event(
            SecurityEvent.EventType.REAUTH_FAILURE,
            outcome=SecurityEvent.Outcome.FAILURE,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="CURRENT_PASSWORD_INVALID",
            user=user,
            auth_session=session,
            request=request,
        )
        raise DRFValidationError({"current_password": "Current password is incorrect."})

    if user.is_2fa_enabled:
        if not otp:
            abuse_record_failure("REAUTH_SESSION", request=request, user=user, auth_session=session, account=user.email)
            abuse_record_failure("REAUTH_ACCOUNT", request=request, user=user, account=user.email)
            record_security_event(
                SecurityEvent.EventType.STEP_UP_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="INVALID_OTP",
                user=user,
                auth_session=session,
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            record_security_event(
                SecurityEvent.EventType.REAUTH_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="INVALID_OTP",
                user=user,
                auth_session=session,
                request=request,
            )
            raise DRFValidationError({"otp": "OTP is required."})
        if not pyotp.TOTP(user.tfa_secret).verify(otp, valid_window=1):
            abuse_record_failure("REAUTH_SESSION", request=request, user=user, auth_session=session, account=user.email)
            abuse_record_failure("REAUTH_ACCOUNT", request=request, user=user, account=user.email)
            record_security_event(
                SecurityEvent.EventType.STEP_UP_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="INVALID_OTP",
                user=user,
                auth_session=session,
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            record_security_event(
                SecurityEvent.EventType.REAUTH_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="INVALID_OTP",
                user=user,
                auth_session=session,
                request=request,
            )
            raise DRFValidationError({"otp": "Invalid OTP."})
        strength = "mfa"
        authentication_method = "password+totp"
    else:
        strength = "password"
        authentication_method = "password"

    touch_session(session, request=request, authentication_strength=strength)
    abuse_record_success(["REAUTH_SESSION", "REAUTH_ACCOUNT"], request=request, user=user, auth_session=session, account=user.email)
    record_security_event(
        SecurityEvent.EventType.STEP_UP_SUCCESS,
        outcome=SecurityEvent.Outcome.SUCCESS,
        severity=SecurityEvent.Severity.INFO,
        reason_code=authentication_method.replace("+", "_").upper(),
        user=user,
        auth_session=session,
        request=request,
        metadata={
            "authentication_method": authentication_method,
            "required_strength": strength,
        },
    )
    record_security_event(
        SecurityEvent.EventType.REAUTH_SUCCESS,
        outcome=SecurityEvent.Outcome.SUCCESS,
        severity=SecurityEvent.Severity.INFO,
        reason_code=authentication_method.replace("+", "_").upper(),
        user=user,
        auth_session=session,
        request=request,
        metadata={"authentication_method": authentication_method},
    )
    return session


def change_password(
    *,
    user,
    session,
    current_password: str,
    new_password: str,
    request=None,
):
    decision = abuse_check("PASSWORD_CHANGE_SESSION", request=request, user=user, auth_session=session, account=user.email)
    if not decision.allowed:
        raise exceptions.Throttled(wait=decision.retry_after_seconds)

    decision = abuse_check("PASSWORD_CHANGE_ACCOUNT", request=request, user=user, account=user.email)
    if not decision.allowed:
        raise exceptions.Throttled(wait=decision.retry_after_seconds)

    require_step_up(
        session,
        STEP_UP_POLICIES["PASSWORD_CHANGE"],
        request=request,
        user=user,
        operation="PASSWORD_CHANGE",
        failure_event=SecurityEvent.EventType.STEP_UP_REQUIRED,
    )

    if not user.check_password(current_password):
        abuse_record_failure("PASSWORD_CHANGE_SESSION", request=request, user=user, auth_session=session, account=user.email)
        abuse_record_failure("PASSWORD_CHANGE_ACCOUNT", request=request, user=user, account=user.email)
        record_security_event(
            SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE,
            outcome=SecurityEvent.Outcome.FAILURE,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="CURRENT_PASSWORD_INVALID",
            user=user,
            auth_session=session,
            request=request,
        )
        raise DRFValidationError({"current_password": "Current password is incorrect."})

    try:
        validate_password(new_password, user=user)
    except ValidationError as exc:
        abuse_record_failure("PASSWORD_CHANGE_SESSION", request=request, user=user, auth_session=session, account=user.email)
        abuse_record_failure("PASSWORD_CHANGE_ACCOUNT", request=request, user=user, account=user.email)
        record_security_event(
            SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE,
            outcome=SecurityEvent.Outcome.FAILURE,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="PASSWORD_POLICY_REJECTED",
            user=user,
            auth_session=session,
            request=request,
            metadata={"errors": exc.messages},
        )
        raise DRFValidationError({"new_password": exc.messages})

    user.set_password(new_password)
    user.save(update_fields=["password"])
    revoked_count = revoke_other_sessions(user, keep_session=session, reason="PASSWORD_CHANGE")
    touch_session(session, request=request, authentication_strength=session.authentication_strength or "password")
    abuse_record_success(["PASSWORD_CHANGE_SESSION", "PASSWORD_CHANGE_ACCOUNT"], request=request, user=user, auth_session=session, account=user.email)
    record_security_event(
        SecurityEvent.EventType.PASSWORD_CHANGE_SUCCESS,
        outcome=SecurityEvent.Outcome.SUCCESS,
        severity=SecurityEvent.Severity.INFO,
        reason_code="PASSWORD_CHANGE",
        user=user,
        auth_session=session,
        request=request,
        metadata={"sessions_revoked": revoked_count},
    )
    return revoked_count


def disable_mfa(
    *,
    user,
    session,
    current_password: str,
    otp: str | None = None,
    request=None,
):
    decision = abuse_check("MFA_CHANGE_SESSION", request=request, user=user, auth_session=session, account=user.email)
    if not decision.allowed:
        raise exceptions.Throttled(wait=decision.retry_after_seconds)

    require_step_up(
        session,
        STEP_UP_POLICIES["MFA_DISABLE"],
        request=request,
        user=user,
        operation="MFA_DISABLE",
        failure_event=SecurityEvent.EventType.STEP_UP_REQUIRED,
    )

    if not user.is_2fa_enabled:
        record_security_event(
            SecurityEvent.EventType.MFA_CHANGE_DENIED,
            outcome=SecurityEvent.Outcome.DENIED,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="MFA_NOT_ENABLED",
            user=user,
            auth_session=session,
            request=request,
        )
        raise DRFValidationError({"is_2fa_enabled": "MFA is not enabled."})

    if not user.check_password(current_password):
        abuse_record_failure("MFA_CHANGE_SESSION", request=request, user=user, auth_session=session, account=user.email)
        record_security_event(
            SecurityEvent.EventType.MFA_CHANGE_DENIED,
            outcome=SecurityEvent.Outcome.DENIED,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="CURRENT_PASSWORD_INVALID",
            user=user,
            auth_session=session,
            request=request,
        )
        raise DRFValidationError({"current_password": "Current password is incorrect."})

    if not otp:
        abuse_record_failure("MFA_CHANGE_SESSION", request=request, user=user, auth_session=session, account=user.email)
        record_security_event(
            SecurityEvent.EventType.MFA_CHANGE_DENIED,
            outcome=SecurityEvent.Outcome.DENIED,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="INVALID_OTP",
            user=user,
            auth_session=session,
            request=request,
        )
        raise DRFValidationError({"otp": "OTP is required."})

    if not pyotp.TOTP(user.tfa_secret).verify(otp, valid_window=1):
        abuse_record_failure("MFA_CHANGE_SESSION", request=request, user=user, auth_session=session, account=user.email)
        record_security_event(
            SecurityEvent.EventType.MFA_CHANGE_DENIED,
            outcome=SecurityEvent.Outcome.DENIED,
            severity=SecurityEvent.Severity.WARNING,
            reason_code="INVALID_OTP",
            user=user,
            auth_session=session,
            request=request,
        )
        raise DRFValidationError({"otp": "Invalid OTP."})

    user.is_2fa_enabled = False
    user.is_2fa_setup_in_progress = False
    user.tfa_secret = ""
    user.save(update_fields=["is_2fa_enabled", "is_2fa_setup_in_progress", "tfa_secret"])
    revoked_count = revoke_other_sessions(user, keep_session=session, reason="MFA_DISABLED")
    touch_session(session, request=request, authentication_strength="password")
    abuse_record_success("MFA_CHANGE_SESSION", request=request, user=user, auth_session=session, account=user.email)
    record_security_event(
        SecurityEvent.EventType.MFA_DISABLED,
        outcome=SecurityEvent.Outcome.REVOKED,
        severity=SecurityEvent.Severity.HIGH,
        reason_code="MFA_DISABLED",
        user=user,
        auth_session=session,
        request=request,
        metadata={"sessions_revoked": revoked_count},
    )
    return revoked_count


def mark_account_disabled(*, user, request=None):
    now = timezone.now()
    sessions = list(AuthSession.objects.filter(user=user, revoked_at__isnull=True))
    session_ids = [session.id for session in sessions]
    if session_ids:
        AuthSession.objects.filter(id__in=session_ids).update(
            revoked_at=now,
            revocation_reason="ACCOUNT_DISABLED",
            last_seen_at=now,
        )

    UserToken.objects.filter(
        user=user,
        revoked_at__isnull=True,
    ).update(
        is_revoked=True,
        revoked_at=now,
        revocation_reason="ACCOUNT_DISABLED",
    )

    for session in sessions:
        record_security_event(
            SecurityEvent.EventType.SESSION_REVOKED,
            outcome=SecurityEvent.Outcome.REVOKED,
            severity=SecurityEvent.Severity.INFO,
            reason_code="ACCOUNT_DISABLED",
            user=user,
            auth_session=session,
            metadata={"reason": "ACCOUNT_DISABLED"},
        )

    revoked_count = len(session_ids)
    record_security_event(
        SecurityEvent.EventType.ACCOUNT_DISABLED,
        outcome=SecurityEvent.Outcome.REVOKED,
        severity=SecurityEvent.Severity.HIGH,
        reason_code="ACCOUNT_DISABLED",
        user=user,
        request=request,
        metadata={"sessions_revoked": revoked_count},
    )
    return revoked_count
