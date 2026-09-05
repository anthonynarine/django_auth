"""Read helpers for security audit data."""

from __future__ import annotations

from datetime import timedelta

from django.db.models import Count, Q
from django.utils import timezone

from security.models import SecurityControl, SecurityEvent, SecurityEvidence, SecurityFinding
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
    queryset = SecurityEvent.objects.select_related("user", "auth_session", "auth_session__user")
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


def list_security_controls(*, domain=None, status=None, control_type=None):
    queryset = SecurityControl.objects.all()
    if domain:
        queryset = queryset.filter(domain=domain)
    if status:
        queryset = queryset.filter(status=status)
    if control_type:
        queryset = queryset.filter(control_type=control_type)
    return queryset.order_by("domain", "control_key")


def get_security_control(control_key: str):
    return SecurityControl.objects.get(control_key=control_key)


def list_security_evidence(
    *,
    control=None,
    evidence_type=None,
    result=None,
    source=None,
    observed_from=None,
    observed_to=None,
):
    queryset = SecurityEvidence.objects.select_related("control")
    if control:
        queryset = queryset.filter(control__control_key=control)
    if evidence_type:
        queryset = queryset.filter(evidence_type=evidence_type)
    if result:
        queryset = queryset.filter(result=result)
    if source:
        queryset = queryset.filter(Q(source_type=source) | Q(source_name=source))
    if observed_from:
        queryset = queryset.filter(observed_at__gte=observed_from)
    if observed_to:
        queryset = queryset.filter(observed_at__lte=observed_to)
    return queryset.order_by("-observed_at", "-created_at", "-id")


def list_security_findings(
    *,
    status=None,
    severity=None,
    domain=None,
    control=None,
    affected_system=None,
):
    queryset = SecurityFinding.objects.select_related("control")
    if status:
        queryset = queryset.filter(status=status)
    if severity:
        queryset = queryset.filter(severity=severity)
    if domain:
        queryset = queryset.filter(control__domain=domain)
    if control:
        queryset = queryset.filter(control__control_key=control)
    if affected_system:
        queryset = queryset.filter(affected_system=affected_system)
    return queryset.order_by("-last_seen_at", "-created_at", "-id")


def _status_counts(queryset):
    counts = {status.lower(): 0 for status, _ in SecurityControl.Status.choices}
    for row in queryset.values("status").annotate(count=Count("id")):
        counts[row["status"].lower()] = row["count"]
    return counts


def _open_finding_counts(queryset):
    active = queryset.exclude(
        status__in=[
            SecurityFinding.Status.RESOLVED,
            SecurityFinding.Status.ACCEPTED_RISK,
            SecurityFinding.Status.FALSE_POSITIVE,
        ]
    )
    counts = {severity.lower(): 0 for severity, _ in SecurityEvent.Severity.choices}
    for row in active.values("severity").annotate(count=Count("id")):
        counts[row["severity"].lower()] = row["count"]
    return counts


def derive_overall_posture_status(control_counts: dict[str, int], finding_counts: dict[str, int]) -> str:
    if finding_counts.get("critical", 0) or control_counts.get("control_failure", 0):
        return SecurityControl.Status.CONTROL_FAILURE
    if any(finding_counts.get(key, 0) for key in ("high", "warning")):
        return SecurityControl.Status.NEEDS_ATTENTION
    if control_counts.get("needs_attention", 0):
        return SecurityControl.Status.NEEDS_ATTENTION
    if control_counts.get("unknown", 0):
        return SecurityControl.Status.UNKNOWN
    applicable = sum(count for key, count in control_counts.items() if key != "not_applicable")
    if applicable and control_counts.get("healthy", 0) == applicable:
        return SecurityControl.Status.HEALTHY
    return SecurityControl.Status.UNKNOWN


def get_security_posture():
    controls = SecurityControl.objects.all()
    findings = SecurityFinding.objects.all()
    control_counts = _status_counts(controls)
    finding_counts = _open_finding_counts(findings)
    latest_evaluation = (
        controls.exclude(last_evaluated_at__isnull=True)
        .order_by("-last_evaluated_at")
        .values_list("last_evaluated_at", flat=True)
        .first()
    )
    overall_status = derive_overall_posture_status(control_counts, finding_counts)
    return {
        "overall_status": overall_status,
        "overall_status_label": SecurityControl.Status(overall_status).label,
        "controls": control_counts,
        "open_findings": finding_counts,
        "last_evaluated_at": latest_evaluation,
    }


def get_security_domains():
    domains = []
    open_statuses = [
        SecurityFinding.Status.OPEN,
        SecurityFinding.Status.ACKNOWLEDGED,
    ]
    for domain, label in SecurityControl.Domain.choices:
        controls = SecurityControl.objects.filter(domain=domain)
        findings = SecurityFinding.objects.filter(control__domain=domain, status__in=open_statuses)
        domains.append({
            "key": domain,
            "label": label,
            "description": _domain_description(domain),
            "controls": _status_counts(controls),
            "open_findings": _open_finding_counts(findings),
        })
    return domains


def _domain_description(domain: str) -> str:
    descriptions = {
        SecurityControl.Domain.IDENTITY: "Authentication and account identity controls.",
        SecurityControl.Domain.SESSION: "Session authority, revocation, and token lifecycle controls.",
        SecurityControl.Domain.MFA: "Multi-factor authentication controls.",
        SecurityControl.Domain.ASSURANCE: "Recent authentication and step-up assurance controls.",
        SecurityControl.Domain.ABUSE_CONTROL: "Rate limiting, throttling, and abuse prevention controls.",
        SecurityControl.Domain.AUDIT: "Security audit and Observatory access controls.",
        SecurityControl.Domain.AUTHORIZATION: "Authorization and access-decision controls.",
        SecurityControl.Domain.DATA_PROTECTION: "Data handling and protection controls.",
        SecurityControl.Domain.DATABASE: "Database security controls.",
        SecurityControl.Domain.INFRASTRUCTURE: "Infrastructure security controls.",
        SecurityControl.Domain.BACKUP_RECOVERY: "Backup and restore readiness controls.",
        SecurityControl.Domain.INCIDENT_RESPONSE: "Incident response preparedness controls.",
        SecurityControl.Domain.MONITORING: "Security monitoring controls.",
        SecurityControl.Domain.SECURE_SDLC: "Secure software delivery controls.",
        SecurityControl.Domain.VULNERABILITY_MANAGEMENT: "Vulnerability management controls.",
        SecurityControl.Domain.GOVERNANCE: "Security governance controls.",
        SecurityControl.Domain.VENDOR_RISK: "Vendor risk controls.",
        SecurityControl.Domain.COMPLIANCE_EVIDENCE: "Compliance evidence controls.",
        SecurityControl.Domain.AGENT_SECURITY: "AI agent security controls.",
    }
    return descriptions.get(domain, "Security controls in this domain.")
