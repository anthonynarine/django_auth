"""Write helpers for security events."""

from __future__ import annotations

import logging

from django.db import IntegrityError, transaction
from django.utils import timezone

from security.control_registry import get_control_definitions
from security.models import SecurityControl, SecurityEvent, SecurityEvidence, SecurityFinding
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
        SecurityEvent.EventType.STEP_UP_REQUIRED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.STEP_UP_SUCCESS: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.REAUTH_SUCCESS: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.PASSWORD_RESET_REQUESTED: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.PASSWORD_RESET_COMPLETED: SecurityEvent.Outcome.SUCCESS,
        SecurityEvent.EventType.LOGIN_FAILURE: SecurityEvent.Outcome.FAILURE,
        SecurityEvent.EventType.MFA_FAILURE: SecurityEvent.Outcome.FAILURE,
        SecurityEvent.EventType.MFA_CHANGE_DENIED: SecurityEvent.Outcome.DENIED,
        SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE: SecurityEvent.Outcome.FAILURE,
        SecurityEvent.EventType.STEP_UP_FAILURE: SecurityEvent.Outcome.FAILURE,
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
        SecurityEvent.EventType.STEP_UP_REQUIRED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.STEP_UP_SUCCESS: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.REAUTH_SUCCESS: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.PASSWORD_RESET_REQUESTED: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.PASSWORD_RESET_COMPLETED: SecurityEvent.Severity.INFO,
        SecurityEvent.EventType.LOGIN_FAILURE: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.MFA_FAILURE: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.MFA_CHANGE_DENIED: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE: SecurityEvent.Severity.WARNING,
        SecurityEvent.EventType.STEP_UP_FAILURE: SecurityEvent.Severity.WARNING,
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


def sync_security_control_registry() -> dict[str, int]:
    """Synchronize code-defined controls without marking them healthy."""

    created = 0
    updated = 0
    for definition in get_control_definitions():
        defaults = {
            "domain": definition.domain,
            "title": definition.title,
            "description": definition.description,
            "control_type": definition.control_type,
            "severity_if_failed": definition.severity_if_failed,
            "lifecycle": definition.lifecycle,
        }
        control, was_created = SecurityControl.objects.update_or_create(
            control_key=definition.control_key,
            defaults=defaults,
        )
        if was_created:
            created += 1
            continue
        updated += 1
        if not control.status:
            control.status = SecurityControl.Status.UNKNOWN
            control.save(update_fields=["status", "updated_at"])
    return {"created": created, "updated": updated}


def create_security_evidence(
    *,
    control: SecurityControl | str,
    evidence_type: str,
    result: str,
    title: str,
    summary: str = "",
    observed_at=None,
    valid_until=None,
    source_type: str = "",
    source_name: str = "",
    source_reference: str = "",
    metadata: dict | None = None,
) -> SecurityEvidence:
    """Append sanitized evidence for a control and refresh control status."""

    if isinstance(control, str):
        control = SecurityControl.objects.get(control_key=control)
    evidence = SecurityEvidence.objects.create(
        control=control,
        evidence_type=evidence_type,
        source_type=source_type,
        source_name=source_name,
        source_reference=source_reference,
        title=title,
        summary=summary,
        result=result,
        observed_at=observed_at or timezone.now(),
        valid_until=valid_until,
        metadata=sanitize_security_metadata(metadata or {}),
    )
    refresh_control_status(control)
    return evidence


def _status_from_latest_evidence(control: SecurityControl, now) -> tuple[str, str, object | None]:
    latest = control.evidence.order_by("-observed_at", "-created_at", "-id").first()
    if not latest:
        return (
            SecurityControl.Status.UNKNOWN,
            "No usable evidence has been recorded for this control.",
            None,
        )
    if latest.valid_until and latest.valid_until < now:
        return (
            SecurityControl.Status.NEEDS_ATTENTION,
            "The latest evidence for this control is stale.",
            latest,
        )
    if latest.result == SecurityEvidence.Result.FAIL:
        return (
            SecurityControl.Status.CONTROL_FAILURE,
            "The latest authoritative evidence reports a failure.",
            latest,
        )
    if latest.result == SecurityEvidence.Result.WARNING:
        return (
            SecurityControl.Status.NEEDS_ATTENTION,
            "The latest authoritative evidence requires follow-up.",
            latest,
        )
    if latest.result == SecurityEvidence.Result.PASS:
        return (
            SecurityControl.Status.HEALTHY,
            "The latest authoritative evidence reports the control is satisfied.",
            latest,
        )
    return (
        SecurityControl.Status.UNKNOWN,
        "The latest evidence is informational and does not establish control health.",
        latest,
    )


def refresh_control_status(control: SecurityControl | str) -> SecurityControl:
    """Evaluate one control from trusted evidence only."""

    if isinstance(control, str):
        control = SecurityControl.objects.get(control_key=control)
    now = timezone.now()
    if control.status == SecurityControl.Status.NOT_APPLICABLE:
        control.last_evaluated_at = now
        control.status_reason = "The control has been explicitly marked not applicable."
        control.save(update_fields=["last_evaluated_at", "status_reason", "updated_at"])
        return control

    status, reason, latest = _status_from_latest_evidence(control, now)
    control.status = status
    control.status_reason = reason
    control.last_evaluated_at = now
    control.last_evidence_at = latest.observed_at if latest else None
    control.save(update_fields=[
        "status",
        "status_reason",
        "last_evaluated_at",
        "last_evidence_at",
        "updated_at",
    ])
    return control


def refresh_all_control_statuses() -> int:
    count = 0
    for control in SecurityControl.objects.all():
        refresh_control_status(control)
        count += 1
    return count


def open_security_finding(
    *,
    finding_key: str,
    control: SecurityControl | str,
    title: str,
    description: str,
    severity: str | None = None,
    expected_behavior: str = "",
    observed_behavior: str = "",
    affected_system: str = "",
    affected_component: str = "",
    source_type: str = "",
    source_reference: str = "",
    evidence: list[SecurityEvidence] | None = None,
    related_events: list[SecurityEvent] | None = None,
    metadata: dict | None = None,
) -> tuple[SecurityFinding, bool]:
    """Open or dedupe a finding by stable finding_key."""

    if isinstance(control, str):
        control = SecurityControl.objects.get(control_key=control)
    now = timezone.now()
    payload = {
        "control": control,
        "severity": severity or control.severity_if_failed,
        "status": SecurityFinding.Status.OPEN,
        "title": title,
        "description": description,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior,
        "affected_system": affected_system,
        "affected_component": affected_component,
        "source_type": source_type,
        "source_reference": source_reference,
        "first_seen_at": now,
        "last_seen_at": now,
        "metadata": sanitize_security_metadata(metadata or {}),
    }

    with transaction.atomic():
        try:
            finding, created = SecurityFinding.objects.select_for_update().get_or_create(
                finding_key=finding_key,
                defaults=payload,
            )
        except IntegrityError:
            finding = SecurityFinding.objects.select_for_update().get(finding_key=finding_key)
            created = False

        if not created:
            finding.last_seen_at = now
            finding.metadata = sanitize_security_metadata(metadata or finding.metadata or {})
            if finding.status in (
                SecurityFinding.Status.RESOLVED,
                SecurityFinding.Status.ACCEPTED_RISK,
                SecurityFinding.Status.FALSE_POSITIVE,
            ):
                finding.status = SecurityFinding.Status.OPEN
                finding.resolved_at = None
                finding.resolution_summary = ""
            finding.save(update_fields=[
                "last_seen_at",
                "metadata",
                "status",
                "resolved_at",
                "resolution_summary",
                "updated_at",
            ])
        if evidence:
            finding.evidence.add(*evidence)
        if related_events:
            finding.related_events.add(*related_events)
    return finding, created


def acknowledge_security_finding(finding: SecurityFinding | str) -> SecurityFinding:
    finding = _get_finding(finding)
    finding.status = SecurityFinding.Status.ACKNOWLEDGED
    finding.resolved_at = None
    finding.save(update_fields=["status", "resolved_at", "updated_at"])
    return finding


def resolve_security_finding(finding: SecurityFinding | str, *, resolution_summary: str = "") -> SecurityFinding:
    finding = _get_finding(finding)
    finding.status = SecurityFinding.Status.RESOLVED
    finding.resolved_at = timezone.now()
    finding.resolution_summary = resolution_summary[:4096]
    finding.save(update_fields=["status", "resolved_at", "resolution_summary", "updated_at"])
    return finding


def accept_security_risk(finding: SecurityFinding | str, *, resolution_summary: str = "") -> SecurityFinding:
    finding = _get_finding(finding)
    finding.status = SecurityFinding.Status.ACCEPTED_RISK
    finding.resolved_at = timezone.now()
    finding.resolution_summary = resolution_summary[:4096]
    finding.save(update_fields=["status", "resolved_at", "resolution_summary", "updated_at"])
    return finding


def _get_finding(finding: SecurityFinding | str) -> SecurityFinding:
    if isinstance(finding, SecurityFinding):
        return finding
    return SecurityFinding.objects.get(finding_key=finding)

