"""Code-defined security controls synchronized into durable rows."""

from __future__ import annotations

from dataclasses import dataclass

from security.models import SecurityControl, SecurityEvent


@dataclass(frozen=True, slots=True)
class ControlDefinition:
    control_key: str
    domain: str
    title: str
    description: str
    control_type: str
    severity_if_failed: str
    lifecycle: str = SecurityControl.Lifecycle.IMPLEMENTED


CONTROL_DEFINITIONS = (
    ControlDefinition(
        control_key="GAIT.AUTH.REFRESH_ROTATION",
        domain=SecurityControl.Domain.SESSION,
        title="Refresh credentials are single-use",
        description="Refresh credentials must rotate after use so a consumed credential cannot continue an authenticated session.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.AUTH.REFRESH_REPLAY_PROTECTION",
        domain=SecurityControl.Domain.SESSION,
        title="Refresh replay attempts revoke authentication authority",
        description="Previously consumed refresh credentials must be rejected and the affected session or token family must be revoked according to session security policy.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.SESSION.SERVER_AUTHORITY",
        domain=SecurityControl.Domain.SESSION,
        title="Server-controlled sessions authorize authenticated requests",
        description="Authenticated access tokens must be backed by a live server-side AuthSession when session enforcement applies.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.SESSION.LOGOUT_ALL_REVOCATION",
        domain=SecurityControl.Domain.SESSION,
        title="Logout-all revokes active sessions",
        description="A logout-all operation must revoke active sessions and associated refresh credentials for the account.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.MFA.TOTP",
        domain=SecurityControl.Domain.MFA,
        title="TOTP multi-factor authentication is enforced when enabled",
        description="Accounts with TOTP multi-factor authentication enabled must complete the additional factor before authenticated sessions are issued.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.ASSURANCE.STEP_UP",
        domain=SecurityControl.Domain.ASSURANCE,
        title="Sensitive actions require step-up assurance",
        description="Sensitive account operations must require recent or stronger authentication when the current session assurance is insufficient.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.ABUSE.POSTGRES_ENFORCEMENT",
        domain=SecurityControl.Domain.ABUSE_CONTROL,
        title="Abuse controls are enforced with durable counters",
        description="Noisy authentication flows must use PostgreSQL-backed AbuseCounter state to throttle or block abusive request patterns across workers.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.AUDIT.SECURITY_EVENTS",
        domain=SecurityControl.Domain.AUDIT,
        title="Security events are durably recorded",
        description="Authentication, session, MFA, account, abuse, and step-up security activity must be recorded as durable SecurityEvent evidence.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.AUDIT.OBSERVATORY_ACCESS",
        domain=SecurityControl.Domain.AUDIT,
        title="Security Observatory access is staff-only",
        description="Security Observatory APIs must deny anonymous and normal authenticated users while allowing authorized staff viewers.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
    ControlDefinition(
        control_key="GAIT.ACCOUNT.RESET_ENUMERATION_PROTECTION",
        domain=SecurityControl.Domain.IDENTITY,
        title="Password reset requests protect account enumeration",
        description="Password reset request behavior must avoid revealing to the requester whether an account exists.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.WARNING,
    ),
    ControlDefinition(
        control_key="GAIT.ACCOUNT.DISABLED_USER_ENFORCEMENT",
        domain=SecurityControl.Domain.IDENTITY,
        title="Disabled users cannot authenticate or continue sessions",
        description="Inactive accounts must be denied authentication and protected resource access while inactive.",
        control_type=SecurityControl.ControlType.LIVE,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    ),
)


def get_control_definitions() -> tuple[ControlDefinition, ...]:
    return CONTROL_DEFINITIONS
