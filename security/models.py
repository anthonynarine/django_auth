"""Durable security audit models."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


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
        REAUTH_SUCCESS = "REAUTH_SUCCESS", "Reauthentication success"
        REAUTH_FAILURE = "REAUTH_FAILURE", "Reauthentication failure"
        PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED", "Password reset requested"
        PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED", "Password reset completed"
        ACCOUNT_DISABLED = "ACCOUNT_DISABLED", "Account disabled"
        INACTIVE_USER_DENIED = "INACTIVE_USER_DENIED", "Inactive user denied"
        SESSION_ACCESS_DENIED = "SESSION_ACCESS_DENIED", "Session access denied"

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

