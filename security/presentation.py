"""Deterministic human presentation for Security Observatory evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Mapping

from django.utils import timezone

from security.models import SecurityEvent
from user.models import AuthSession


class EventCategory:
    AUTHENTICATION = "AUTHENTICATION"
    SESSION_SECURITY = "SESSION_SECURITY"
    MFA = "MFA"
    ACCOUNT_SECURITY = "ACCOUNT_SECURITY"
    ABUSE_CONTROL = "ABUSE_CONTROL"
    STEP_UP = "STEP_UP"
    SYSTEM_SECURITY = "SYSTEM_SECURITY"


CATEGORY_LABELS = {
    EventCategory.AUTHENTICATION: "Authentication",
    EventCategory.SESSION_SECURITY: "Session security",
    EventCategory.MFA: "Multi-factor authentication",
    EventCategory.ACCOUNT_SECURITY: "Account security",
    EventCategory.ABUSE_CONTROL: "Abuse control",
    EventCategory.STEP_UP: "Step-up verification",
    EventCategory.SYSTEM_SECURITY: "System security",
}

SEVERITY_LABELS = {
    SecurityEvent.Severity.INFO: "Normal activity",
    SecurityEvent.Severity.WARNING: "Needs attention",
    SecurityEvent.Severity.HIGH: "Security concern",
    SecurityEvent.Severity.CRITICAL: "Immediate attention",
}


@dataclass(frozen=True, slots=True)
class EventPresentation:
    title: str
    description: str
    category: str
    category_label: str
    severity_label: str
    system_response: str
    impact_summary: str
    recommended_action: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _EventTemplate:
    title: str
    description: str
    category: str
    system_response: str
    impact_summary: str
    recommended_action: str


UNKNOWN_EVENT_TEMPLATE = _EventTemplate(
    title="Security activity recorded",
    description="Gait recorded a security-related event.",
    category=EventCategory.SYSTEM_SECURITY,
    system_response="Recorded",
    impact_summary="Review technical details for more information.",
    recommended_action="Review technical details for more information.",
)


EVENT_TEMPLATES = {
    SecurityEvent.EventType.LOGIN_SUCCESS: _EventTemplate(
        title="Successful sign-in",
        description="A user successfully authenticated and a valid session was established.",
        category=EventCategory.AUTHENTICATION,
        system_response="Allowed",
        impact_summary="An authenticated session was created or continued.",
        recommended_action="No action required.",
    ),
    SecurityEvent.EventType.LOGIN_FAILURE: _EventTemplate(
        title="Sign-in attempt failed",
        description="A sign-in attempt was rejected because the supplied authentication proof was not accepted.",
        category=EventCategory.AUTHENTICATION,
        system_response="Authentication failed",
        impact_summary="No authenticated session was created.",
        recommended_action="No action required unless repeated or unexpected attempts continue.",
    ),
    SecurityEvent.EventType.MFA_SUCCESS: _EventTemplate(
        title="Multi-factor verification succeeded",
        description="The user successfully completed multi-factor authentication.",
        category=EventCategory.MFA,
        system_response="Allowed",
        impact_summary="The authentication flow was allowed to continue.",
        recommended_action="No action required.",
    ),
    SecurityEvent.EventType.MFA_FAILURE: _EventTemplate(
        title="Multi-factor verification failed",
        description="A multi-factor authentication attempt was rejected because the supplied verification proof was not accepted.",
        category=EventCategory.MFA,
        system_response="Authentication failed",
        impact_summary="The multi-factor authentication flow was not completed.",
        recommended_action="No action required unless repeated or unexpected attempts continue.",
    ),
    SecurityEvent.EventType.MFA_ENABLED: _EventTemplate(
        title="Multi-factor authentication enabled",
        description="The user successfully added an authenticator as an additional authentication factor.",
        category=EventCategory.MFA,
        system_response="Allowed",
        impact_summary="Future sign-ins or sensitive actions may require the added factor according to policy.",
        recommended_action="No action required if this change was expected.",
    ),
    SecurityEvent.EventType.MFA_DISABLED: _EventTemplate(
        title="Multi-factor authentication disabled",
        description="Multi-factor authentication was removed from the account.",
        category=EventCategory.MFA,
        system_response="Security factor removed",
        impact_summary="The account no longer has that additional authentication factor enabled.",
        recommended_action="Confirm that the multi-factor authentication removal was authorized.",
    ),
    SecurityEvent.EventType.MFA_CHANGE_DENIED: _EventTemplate(
        title="Multi-factor authentication change denied",
        description="A requested multi-factor authentication change was rejected by security policy.",
        category=EventCategory.MFA,
        system_response="Request blocked",
        impact_summary="The requested multi-factor authentication change was not performed.",
        recommended_action="Review the account if this activity was unexpected.",
    ),
    SecurityEvent.EventType.SESSION_CREATED: _EventTemplate(
        title="Session created",
        description="Gait created a server-controlled authenticated session for the user.",
        category=EventCategory.SESSION_SECURITY,
        system_response="Allowed",
        impact_summary="The session may access protected resources according to normal authorization policy.",
        recommended_action="No action required.",
    ),
    SecurityEvent.EventType.SESSION_REVOKED: _EventTemplate(
        title="Session revoked",
        description="Gait invalidated an authenticated session so it can no longer be used to access protected resources.",
        category=EventCategory.SESSION_SECURITY,
        system_response="Session revoked",
        impact_summary="The affected session can no longer authorize protected requests.",
        recommended_action="No action required if this revocation was expected.",
    ),
    SecurityEvent.EventType.LOGOUT: _EventTemplate(
        title="User signed out",
        description="The current authenticated session was ended.",
        category=EventCategory.SESSION_SECURITY,
        system_response="Session revoked",
        impact_summary="The signed-out session can no longer authorize protected requests.",
        recommended_action="No action required.",
    ),
    SecurityEvent.EventType.LOGOUT_ALL: _EventTemplate(
        title="All sessions signed out",
        description="Gait ended all active sessions for the account according to the requested logout-all operation.",
        category=EventCategory.SESSION_SECURITY,
        system_response="Sessions revoked",
        impact_summary="The affected sessions can no longer authorize protected requests.",
        recommended_action="No action required if this action was expected.",
    ),
    SecurityEvent.EventType.TOKEN_REFRESHED: _EventTemplate(
        title="Session token refreshed",
        description="A valid refresh credential was exchanged for a new access credential.",
        category=EventCategory.SESSION_SECURITY,
        system_response="Allowed",
        impact_summary="The authenticated session was allowed to continue.",
        recommended_action="No action required.",
    ),
    SecurityEvent.EventType.REFRESH_REPLAY_DETECTED: _EventTemplate(
        title="Previously used session token detected",
        description="A refresh credential that had already been consumed was presented again. Gait rejected the request and revoked the affected session or token family according to security policy.",
        category=EventCategory.SESSION_SECURITY,
        system_response="Request blocked and affected authentication authority revoked",
        impact_summary="The affected authentication authority was revoked according to session security policy.",
        recommended_action="Review the affected account if this activity was unexpected.",
    ),
    SecurityEvent.EventType.PASSWORD_CHANGE_SUCCESS: _EventTemplate(
        title="Password changed",
        description="The account password was successfully changed after the required security checks were satisfied.",
        category=EventCategory.ACCOUNT_SECURITY,
        system_response="Allowed",
        impact_summary="Existing sessions other than the current authorized session may have been revoked according to account security policy.",
        recommended_action="No action required if this change was expected.",
    ),
    SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE: _EventTemplate(
        title="Password change failed",
        description="A password change request was rejected because the supplied proof or request data was not accepted.",
        category=EventCategory.ACCOUNT_SECURITY,
        system_response="Request blocked",
        impact_summary="The account password was not changed.",
        recommended_action="No action required unless repeated or unexpected attempts continue.",
    ),
    SecurityEvent.EventType.PASSWORD_CHANGE_THROTTLED: _EventTemplate(
        title="Too many password-change attempts were throttled",
        description="Gait detected repeated password-change attempts and temporarily slowed additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily throttled",
        impact_summary="Additional password-change attempts may be delayed during the throttle window.",
        recommended_action="No action required unless the activity was unexpected.",
    ),
    SecurityEvent.EventType.PASSWORD_CHANGE_BLOCKED: _EventTemplate(
        title="Too many password-change attempts were blocked",
        description="Gait detected repeated password-change attempts and temporarily prevented additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily blocked",
        impact_summary="Additional password-change attempts are blocked during the temporary block window.",
        recommended_action="Review the account if this activity was unexpected.",
    ),
    SecurityEvent.EventType.STEP_UP_REQUIRED: _EventTemplate(
        title="Additional identity verification required",
        description="A sensitive action required authentication that was stronger or more recent than the user's current session assurance.",
        category=EventCategory.STEP_UP,
        system_response="Additional authentication required",
        impact_summary="The requested sensitive action was paused until additional verification is completed.",
        recommended_action="No action required if the user intentionally initiated the sensitive operation.",
    ),
    SecurityEvent.EventType.STEP_UP_SUCCESS: _EventTemplate(
        title="Additional identity verification completed",
        description="The user successfully completed the additional verification required for a sensitive action.",
        category=EventCategory.STEP_UP,
        system_response="Allowed",
        impact_summary="The sensitive action may continue according to normal authorization policy.",
        recommended_action="No action required.",
    ),
    SecurityEvent.EventType.STEP_UP_FAILURE: _EventTemplate(
        title="Additional identity verification failed",
        description="The additional verification required for a sensitive action was rejected.",
        category=EventCategory.STEP_UP,
        system_response="Authentication failed",
        impact_summary="The requested sensitive action was not performed.",
        recommended_action="No action required unless repeated or unexpected attempts continue.",
    ),
    SecurityEvent.EventType.REAUTH_SUCCESS: _EventTemplate(
        title="Password reauthentication succeeded",
        description="The user successfully refreshed their recent authentication proof with a password.",
        category=EventCategory.STEP_UP,
        system_response="Allowed",
        impact_summary="Sensitive actions that require recent password authentication may continue according to policy.",
        recommended_action="No action required.",
    ),
    SecurityEvent.EventType.REAUTH_FAILURE: _EventTemplate(
        title="Password reauthentication failed",
        description="A password reauthentication attempt was rejected because the supplied password was not accepted.",
        category=EventCategory.STEP_UP,
        system_response="Authentication failed",
        impact_summary="The requested sensitive action was not performed.",
        recommended_action="No action required unless repeated or unexpected attempts continue.",
    ),
    SecurityEvent.EventType.PASSWORD_RESET_REQUESTED: _EventTemplate(
        title="Password reset requested",
        description="A password reset flow was requested. Gait uses a generic response so this event does not prove whether an account exists to the requester.",
        category=EventCategory.ACCOUNT_SECURITY,
        system_response="Request accepted",
        impact_summary="If an eligible account matched the request, password reset instructions may have been sent.",
        recommended_action="No action required unless repeated or unexpected requests continue.",
    ),
    SecurityEvent.EventType.PASSWORD_RESET_COMPLETED: _EventTemplate(
        title="Password reset completed",
        description="An account password was successfully reset using the password reset flow.",
        category=EventCategory.ACCOUNT_SECURITY,
        system_response="Allowed",
        impact_summary="The account password was changed.",
        recommended_action="No action required if this reset was expected.",
    ),
    SecurityEvent.EventType.ACCOUNT_DISABLED: _EventTemplate(
        title="Account disabled",
        description="The account was disabled and active sessions were revoked according to account security policy.",
        category=EventCategory.ACCOUNT_SECURITY,
        system_response="Account disabled and sessions revoked",
        impact_summary="The disabled account can no longer authenticate while it remains inactive.",
        recommended_action="Confirm that the account disablement was authorized.",
    ),
    SecurityEvent.EventType.INACTIVE_USER_DENIED: _EventTemplate(
        title="Inactive account access denied",
        description="A request associated with an inactive account was denied.",
        category=EventCategory.ACCOUNT_SECURITY,
        system_response="Request blocked",
        impact_summary="The inactive account was not allowed to access protected resources.",
        recommended_action="Confirm the account status if this activity was unexpected.",
    ),
    SecurityEvent.EventType.SESSION_ACCESS_DENIED: _EventTemplate(
        title="Access from an invalid session was blocked",
        description="The request presented authentication credentials, but the server-side session was no longer authorized.",
        category=EventCategory.SESSION_SECURITY,
        system_response="Request blocked",
        impact_summary="The request was not authorized by the presented session.",
        recommended_action="Review related activity if this denial was unexpected.",
    ),
    SecurityEvent.EventType.LOGIN_THROTTLED: _EventTemplate(
        title="Too many sign-in attempts were throttled",
        description="Gait detected repeated sign-in attempts and temporarily slowed additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily throttled",
        impact_summary="Additional sign-in attempts may be delayed during the throttle window.",
        recommended_action="No action required unless the activity was unexpected.",
    ),
    SecurityEvent.EventType.LOGIN_BLOCKED: _EventTemplate(
        title="Too many sign-in attempts were blocked",
        description="Gait detected repeated sign-in attempts and temporarily prevented additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily blocked",
        impact_summary="Additional sign-in attempts are blocked during the temporary block window.",
        recommended_action="Review the account or source if this activity was unexpected.",
    ),
    SecurityEvent.EventType.OTP_THROTTLED: _EventTemplate(
        title="Too many one-time-code attempts were throttled",
        description="Gait detected repeated one-time-code verification attempts and temporarily slowed additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily throttled",
        impact_summary="Additional one-time-code attempts may be delayed during the throttle window.",
        recommended_action="No action required unless the activity was unexpected.",
    ),
    SecurityEvent.EventType.OTP_BLOCKED: _EventTemplate(
        title="Too many one-time-code attempts were blocked",
        description="Gait detected repeated one-time-code verification attempts and temporarily prevented additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily blocked",
        impact_summary="Additional one-time-code attempts are blocked during the temporary block window.",
        recommended_action="Review the account if this activity was unexpected.",
    ),
    SecurityEvent.EventType.PASSWORD_RESET_THROTTLED: _EventTemplate(
        title="Too many password-reset requests were throttled",
        description="Gait detected repeated password-reset requests and temporarily slowed additional requests.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily throttled",
        impact_summary="Additional password-reset requests may be delayed during the throttle window.",
        recommended_action="No action required unless repeated or unexpected requests continue.",
    ),
    SecurityEvent.EventType.PASSWORD_RESET_BLOCKED: _EventTemplate(
        title="Too many password-reset requests were blocked",
        description="Gait detected repeated password-reset requests and temporarily prevented additional requests.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily blocked",
        impact_summary="Additional password-reset requests are blocked during the temporary block window.",
        recommended_action="Review the account or source if this activity was unexpected.",
    ),
    SecurityEvent.EventType.REAUTH_THROTTLED: _EventTemplate(
        title="Too many identity-verification attempts were throttled",
        description="Gait detected repeated failed reauthentication attempts and temporarily slowed additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily throttled",
        impact_summary="Additional verification attempts may be delayed during the throttle window.",
        recommended_action="No action required unless the activity was unexpected.",
    ),
    SecurityEvent.EventType.REAUTH_BLOCKED: _EventTemplate(
        title="Too many identity-verification attempts were blocked",
        description="Gait detected repeated failed reauthentication attempts and temporarily prevented additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily blocked",
        impact_summary="Additional verification attempts are blocked during the temporary block window.",
        recommended_action="Review the account if this activity was unexpected.",
    ),
    SecurityEvent.EventType.MFA_CHANGE_THROTTLED: _EventTemplate(
        title="Too many multi-factor change attempts were throttled",
        description="Gait detected repeated multi-factor authentication change attempts and temporarily slowed additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily throttled",
        impact_summary="Additional multi-factor authentication change attempts may be delayed during the throttle window.",
        recommended_action="No action required unless the activity was unexpected.",
    ),
    SecurityEvent.EventType.MFA_CHANGE_BLOCKED: _EventTemplate(
        title="Too many multi-factor change attempts were blocked",
        description="Gait detected repeated multi-factor authentication change attempts and temporarily prevented additional attempts.",
        category=EventCategory.ABUSE_CONTROL,
        system_response="Temporarily blocked",
        impact_summary="Additional multi-factor authentication change attempts are blocked during the temporary block window.",
        recommended_action="Review the account if this activity was unexpected.",
    ),
}


REASON_OVERRIDES = {
    (SecurityEvent.EventType.STEP_UP_REQUIRED, "RECENT_AUTH_REQUIRED"): {
        "description": "The user's prior authentication was too old for the requested sensitive action.",
    },
    (SecurityEvent.EventType.STEP_UP_REQUIRED, "MFA_REQUIRED"): {
        "description": "The requested sensitive action required multi-factor authentication, but the current session did not meet that requirement.",
    },
    (SecurityEvent.EventType.STEP_UP_REQUIRED, "AUTH_STRENGTH_INSUFFICIENT"): {
        "description": "The current session authentication strength was lower than the level required for the requested sensitive action.",
    },
    (SecurityEvent.EventType.STEP_UP_FAILURE, "INVALID_PASSWORD"): {
        "description": "The additional password verification required for a sensitive action was rejected.",
    },
    (SecurityEvent.EventType.STEP_UP_FAILURE, "INVALID_OTP"): {
        "description": "The additional multi-factor verification required for a sensitive action was rejected.",
    },
    (SecurityEvent.EventType.REAUTH_FAILURE, "INVALID_PASSWORD"): {
        "description": "A password reauthentication attempt was rejected because the supplied password was not accepted.",
    },
    (SecurityEvent.EventType.MFA_FAILURE, "INVALID_OTP"): {
        "description": "A multi-factor authentication attempt was rejected because the supplied one-time code was not accepted.",
    },
}


def _template_for(event_type: str) -> _EventTemplate:
    return EVENT_TEMPLATES.get(event_type, UNKNOWN_EVENT_TEMPLATE)


def _apply_reason_override(template: _EventTemplate, event_type: str, reason_code: str) -> _EventTemplate:
    override = REASON_OVERRIDES.get((event_type, reason_code))
    if not override:
        return template
    return replace(template, **override)


def describe_security_event(event: SecurityEvent) -> EventPresentation:
    """Return deterministic human-facing text for an already-sanitized event."""

    template = _apply_reason_override(
        _template_for(event.event_type),
        event.event_type,
        event.reason_code or "",
    )
    category_label = CATEGORY_LABELS.get(template.category, CATEGORY_LABELS[EventCategory.SYSTEM_SECURITY])
    severity_label = SEVERITY_LABELS.get(event.severity, "Security activity")
    return EventPresentation(
        title=template.title,
        description=template.description,
        category=template.category,
        category_label=category_label,
        severity_label=severity_label,
        system_response=template.system_response,
        impact_summary=template.impact_summary,
        recommended_action=template.recommended_action,
    )


def get_category_labels() -> Mapping[str, str]:
    return CATEGORY_LABELS.copy()


def get_severity_labels() -> Mapping[str, str]:
    return SEVERITY_LABELS.copy()


def describe_session_state(session: AuthSession) -> dict[str, str]:
    if session.revoked_at is not None:
        return {
            "status_code": "REVOKED",
            "status": "Revoked",
            "status_description": "This session has been revoked and can no longer authorize protected requests.",
        }
    if session.expires_at <= timezone.now():
        return {
            "status_code": "EXPIRED",
            "status": "Expired",
            "status_description": "This session has expired and can no longer authorize protected requests.",
        }
    return {
        "status_code": "ACTIVE",
        "status": "Active",
        "status_description": "This session is currently active and may access protected resources according to normal authorization policy.",
    }
