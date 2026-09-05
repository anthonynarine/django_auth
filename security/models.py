"""Durable security audit models."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models

from security.utils import sanitize_security_metadata


class SecurityEvent(models.Model):
    """Append-only security audit record."""

    class EventType(models.TextChoices):
        LOGIN_SUCCESS = "LOGIN_SUCCESS", "Login success"
        LOGIN_FAILURE = "LOGIN_FAILURE", "Login failure"
        MFA_SUCCESS = "MFA_SUCCESS", "MFA success"
        MFA_FAILURE = "MFA_FAILURE", "MFA failure"
        MFA_ENABLED = "MFA_ENABLED", "MFA enabled"
        MFA_DISABLED = "MFA_DISABLED", "MFA disabled"
        MFA_CHANGE_DENIED = "MFA_CHANGE_DENIED", "MFA change denied"
        SESSION_CREATED = "SESSION_CREATED", "Session created"
        SESSION_REVOKED = "SESSION_REVOKED", "Session revoked"
        LOGOUT = "LOGOUT", "Logout"
        LOGOUT_ALL = "LOGOUT_ALL", "Logout all"
        TOKEN_REFRESHED = "TOKEN_REFRESHED", "Token refreshed"
        REFRESH_REPLAY_DETECTED = "REFRESH_REPLAY_DETECTED", "Refresh replay detected"
        PASSWORD_CHANGE_SUCCESS = "PASSWORD_CHANGE_SUCCESS", "Password change success"
        PASSWORD_CHANGE_FAILURE = "PASSWORD_CHANGE_FAILURE", "Password change failure"
        PASSWORD_CHANGE_THROTTLED = "PASSWORD_CHANGE_THROTTLED", "Password change throttled"
        PASSWORD_CHANGE_BLOCKED = "PASSWORD_CHANGE_BLOCKED", "Password change blocked"
        STEP_UP_REQUIRED = "STEP_UP_REQUIRED", "Step-up required"
        STEP_UP_SUCCESS = "STEP_UP_SUCCESS", "Step-up success"
        STEP_UP_FAILURE = "STEP_UP_FAILURE", "Step-up failure"
        REAUTH_SUCCESS = "REAUTH_SUCCESS", "Reauthentication success"
        REAUTH_FAILURE = "REAUTH_FAILURE", "Reauthentication failure"
        PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED", "Password reset requested"
        PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED", "Password reset completed"
        ACCOUNT_DISABLED = "ACCOUNT_DISABLED", "Account disabled"
        INACTIVE_USER_DENIED = "INACTIVE_USER_DENIED", "Inactive user denied"
        SESSION_ACCESS_DENIED = "SESSION_ACCESS_DENIED", "Session access denied"
        LOGIN_THROTTLED = "LOGIN_THROTTLED", "Login throttled"
        LOGIN_BLOCKED = "LOGIN_BLOCKED", "Login blocked"
        OTP_THROTTLED = "OTP_THROTTLED", "OTP throttled"
        OTP_BLOCKED = "OTP_BLOCKED", "OTP blocked"
        PASSWORD_RESET_THROTTLED = "PASSWORD_RESET_THROTTLED", "Password reset throttled"
        PASSWORD_RESET_BLOCKED = "PASSWORD_RESET_BLOCKED", "Password reset blocked"
        REAUTH_THROTTLED = "REAUTH_THROTTLED", "Reauthentication throttled"
        REAUTH_BLOCKED = "REAUTH_BLOCKED", "Reauthentication blocked"
        MFA_CHANGE_THROTTLED = "MFA_CHANGE_THROTTLED", "MFA change throttled"
        MFA_CHANGE_BLOCKED = "MFA_CHANGE_BLOCKED", "MFA change blocked"

    class Outcome(models.TextChoices):
        SUCCESS = "SUCCESS", "Success"
        FAILURE = "FAILURE", "Failure"
        DENIED = "DENIED", "Denied"
        REVOKED = "REVOKED", "Revoked"

    class Severity(models.TextChoices):
        INFO = "INFO", "Info"
        WARNING = "WARNING", "Warning"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=64, choices=EventType.choices)
    outcome = models.CharField(max_length=16, choices=Outcome.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_events",
    )
    auth_session = models.ForeignKey(
        "user.AuthSession",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_events",
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")
    request_method = models.CharField(max_length=16, blank=True, default="")
    request_path = models.CharField(max_length=512, blank=True, default="")
    reason_code = models.CharField(max_length=64, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["created_at"], name="sec_event_created_idx"),
            models.Index(fields=["event_type", "created_at"], name="sec_event_type_created_idx"),
            models.Index(fields=["user", "created_at"], name="sec_event_user_created_idx"),
            models.Index(fields=["auth_session", "created_at"], name="sec_event_session_created_idx"),
            models.Index(fields=["severity", "created_at"], name="sec_event_sev_created_idx"),
        ]
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"{self.event_type} [{self.outcome}]"


class SecurityControl(models.Model):
    """Durable security invariant tracked by the Observatory."""

    class Domain(models.TextChoices):
        IDENTITY = "IDENTITY", "Identity"
        SESSION = "SESSION", "Session"
        MFA = "MFA", "Multi-factor authentication"
        ASSURANCE = "ASSURANCE", "Authentication assurance"
        ABUSE_CONTROL = "ABUSE_CONTROL", "Abuse control"
        AUDIT = "AUDIT", "Audit"
        AUTHORIZATION = "AUTHORIZATION", "Authorization"
        DATA_PROTECTION = "DATA_PROTECTION", "Data protection"
        DATABASE = "DATABASE", "Database"
        INFRASTRUCTURE = "INFRASTRUCTURE", "Infrastructure"
        BACKUP_RECOVERY = "BACKUP_RECOVERY", "Backup & recovery"
        INCIDENT_RESPONSE = "INCIDENT_RESPONSE", "Incident response"
        MONITORING = "MONITORING", "Monitoring"
        SECURE_SDLC = "SECURE_SDLC", "Secure SDLC"
        VULNERABILITY_MANAGEMENT = "VULNERABILITY_MANAGEMENT", "Vulnerability management"
        GOVERNANCE = "GOVERNANCE", "Governance"
        VENDOR_RISK = "VENDOR_RISK", "Vendor risk"
        COMPLIANCE_EVIDENCE = "COMPLIANCE_EVIDENCE", "Compliance evidence"
        AGENT_SECURITY = "AGENT_SECURITY", "Agent security"

    class ControlType(models.TextChoices):
        LIVE = "LIVE", "Live"
        PERIODIC = "PERIODIC", "Periodic"
        DOCUMENTARY = "DOCUMENTARY", "Documentary"
        MANUAL = "MANUAL", "Manual"

    class Status(models.TextChoices):
        HEALTHY = "HEALTHY", "Healthy"
        NEEDS_ATTENTION = "NEEDS_ATTENTION", "Needs attention"
        CONTROL_FAILURE = "CONTROL_FAILURE", "Control failure"
        UNKNOWN = "UNKNOWN", "Unknown"
        NOT_APPLICABLE = "NOT_APPLICABLE", "Not applicable"

    class Lifecycle(models.TextChoices):
        IMPLEMENTED = "IMPLEMENTED", "Implemented"
        PLANNED = "PLANNED", "Planned"
        DEPRECATED = "DEPRECATED", "Deprecated"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    control_key = models.CharField(max_length=128, unique=True)
    domain = models.CharField(max_length=64, choices=Domain.choices)
    title = models.CharField(max_length=160)
    description = models.TextField()
    control_type = models.CharField(max_length=32, choices=ControlType.choices)
    lifecycle = models.CharField(
        max_length=32,
        choices=Lifecycle.choices,
        default=Lifecycle.IMPLEMENTED,
    )
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.UNKNOWN,
    )
    status_reason = models.TextField(blank=True, default="")
    severity_if_failed = models.CharField(
        max_length=16,
        choices=SecurityEvent.Severity.choices,
        default=SecurityEvent.Severity.WARNING,
    )
    last_evaluated_at = models.DateTimeField(null=True, blank=True)
    last_evidence_at = models.DateTimeField(null=True, blank=True)
    next_review_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["domain", "status"], name="sec_ctrl_domain_status_idx"),
            models.Index(fields=["status"], name="sec_ctrl_status_idx"),
            models.Index(fields=["control_type"], name="sec_ctrl_type_idx"),
        ]
        ordering = ["domain", "control_key"]

    def __str__(self):
        return self.control_key


class SecurityEvidence(models.Model):
    """Append-oriented evidence supporting a security control."""

    class EvidenceType(models.TextChoices):
        SECURITY_EVENT = "SECURITY_EVENT", "Security event"
        AUTOMATED_TEST = "AUTOMATED_TEST", "Automated test"
        CI_RESULT = "CI_RESULT", "CI result"
        CONFIGURATION_CHECK = "CONFIGURATION_CHECK", "Configuration check"
        MANUAL_VERIFICATION = "MANUAL_VERIFICATION", "Manual verification"
        POLICY_REVIEW = "POLICY_REVIEW", "Policy review"
        RISK_ASSESSMENT = "RISK_ASSESSMENT", "Risk assessment"
        BACKUP_TEST = "BACKUP_TEST", "Backup test"
        RESTORE_TEST = "RESTORE_TEST", "Restore test"
        VULNERABILITY_SCAN = "VULNERABILITY_SCAN", "Vulnerability scan"
        PENETRATION_TEST = "PENETRATION_TEST", "Penetration test"
        VENDOR_REVIEW = "VENDOR_REVIEW", "Vendor review"
        INCIDENT_EXERCISE = "INCIDENT_EXERCISE", "Incident exercise"
        OTHER = "OTHER", "Other"

    class Result(models.TextChoices):
        PASS = "PASS", "Pass"
        FAIL = "FAIL", "Fail"
        WARNING = "WARNING", "Warning"
        INFORMATIONAL = "INFORMATIONAL", "Informational"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    control = models.ForeignKey(
        SecurityControl,
        on_delete=models.PROTECT,
        related_name="evidence",
    )
    evidence_type = models.CharField(max_length=64, choices=EvidenceType.choices)
    source_type = models.CharField(max_length=64, blank=True, default="")
    source_name = models.CharField(max_length=160, blank=True, default="")
    source_reference = models.CharField(max_length=256, blank=True, default="")
    title = models.CharField(max_length=160)
    summary = models.TextField(blank=True, default="")
    result = models.CharField(max_length=32, choices=Result.choices)
    observed_at = models.DateTimeField()
    valid_until = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["control", "observed_at"], name="sec_evid_ctrl_observed_idx"),
            models.Index(fields=["evidence_type", "observed_at"], name="sec_evid_type_observed_idx"),
            models.Index(fields=["result", "observed_at"], name="sec_evid_result_obs_idx"),
            models.Index(fields=["source_type", "source_name"], name="sec_evid_source_idx"),
            models.Index(fields=["observed_at"], name="sec_evid_observed_idx"),
        ]
        ordering = ["-observed_at", "-created_at", "-id"]

    def __str__(self):
        return f"{self.control.control_key}: {self.result}"

    def save(self, *args, **kwargs):
        self.metadata = sanitize_security_metadata(self.metadata or {})
        super().save(*args, **kwargs)


class SecurityFinding(models.Model):
    """Durable security problem requiring investigation or disposition."""

    class Status(models.TextChoices):
        OPEN = "OPEN", "Open"
        ACKNOWLEDGED = "ACKNOWLEDGED", "Acknowledged"
        RESOLVED = "RESOLVED", "Resolved"
        ACCEPTED_RISK = "ACCEPTED_RISK", "Accepted risk"
        FALSE_POSITIVE = "FALSE_POSITIVE", "False positive"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding_key = models.CharField(max_length=160, unique=True)
    control = models.ForeignKey(
        SecurityControl,
        on_delete=models.PROTECT,
        related_name="findings",
    )
    severity = models.CharField(max_length=16, choices=SecurityEvent.Severity.choices)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.OPEN)
    title = models.CharField(max_length=180)
    description = models.TextField()
    expected_behavior = models.TextField(blank=True, default="")
    observed_behavior = models.TextField(blank=True, default="")
    affected_system = models.CharField(max_length=160, blank=True, default="")
    affected_component = models.CharField(max_length=160, blank=True, default="")
    source_type = models.CharField(max_length=64, blank=True, default="")
    source_reference = models.CharField(max_length=256, blank=True, default="")
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_summary = models.TextField(blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)
    evidence = models.ManyToManyField(SecurityEvidence, blank=True, related_name="findings")
    related_events = models.ManyToManyField(SecurityEvent, blank=True, related_name="findings")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["status", "severity"], name="sec_find_status_sev_idx"),
            models.Index(fields=["control", "status"], name="sec_find_ctrl_status_idx"),
            models.Index(fields=["last_seen_at"], name="sec_find_last_seen_idx"),
            models.Index(fields=["affected_system"], name="sec_find_system_idx"),
        ]
        ordering = ["-last_seen_at", "-created_at", "-id"]

    def __str__(self):
        return f"{self.finding_key} [{self.status}]"

    def save(self, *args, **kwargs):
        self.metadata = sanitize_security_metadata(self.metadata or {})
        super().save(*args, **kwargs)

