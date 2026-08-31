"""Serializers for security audit reads."""

from __future__ import annotations

from django.utils import timezone
from rest_framework import serializers

from security.models import SecurityEvent
from security.utils import humanize_code
from user.models import AuthSession


def _session_status_code(session: AuthSession) -> str:
    if session.revoked_at is not None:
        return "REVOKED"
    if session.expires_at <= timezone.now():
        return "EXPIRED"
    return "ACTIVE"


def _session_status_label(session: AuthSession) -> str:
    return humanize_code(_session_status_code(session))


class SecurityEventSerializer(serializers.ModelSerializer):
    event_label = serializers.SerializerMethodField()
    outcome_label = serializers.SerializerMethodField()
    severity_label = serializers.SerializerMethodField()
    user_email = serializers.SerializerMethodField()
    user_display_name = serializers.SerializerMethodField()
    session_user_email = serializers.SerializerMethodField()
    session_display_name = serializers.SerializerMethodField()
    reason_label = serializers.SerializerMethodField()

    class Meta:
        model = SecurityEvent
        fields = [
            "id",
            "created_at",
            "event_type",
            "event_label",
            "outcome",
            "outcome_label",
            "severity",
            "severity_label",
            "user",
            "user_email",
            "user_display_name",
            "auth_session",
            "session_user_email",
            "session_display_name",
            "ip_address",
            "user_agent",
            "request_method",
            "request_path",
            "reason_code",
            "reason_label",
            "metadata",
        ]
        read_only_fields = fields

    def get_event_label(self, obj):
        return obj.get_event_type_display()

    def get_outcome_label(self, obj):
        return obj.get_outcome_display()

    def get_severity_label(self, obj):
        return obj.get_severity_display()

    def get_user_email(self, obj):
        return obj.user.email if obj.user else None

    def get_user_display_name(self, obj):
        if not obj.user:
            return None
        full_name = f"{obj.user.first_name} {obj.user.last_name}".strip()
        return full_name or obj.user.email

    def get_session_user_email(self, obj):
        return obj.auth_session.user.email if obj.auth_session else None

    def get_session_display_name(self, obj):
        if not obj.auth_session:
            return None
        status = _session_status_label(obj.auth_session)
        return f"{obj.auth_session.user.email} ({status})"

    def get_reason_label(self, obj):
        return humanize_code(obj.reason_code)


class AuthSessionSerializer(serializers.ModelSerializer):
    status_code = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    user_email = serializers.SerializerMethodField()
    user_display_name = serializers.SerializerMethodField()
    session_display_name = serializers.SerializerMethodField()

    class Meta:
        model = AuthSession
        fields = [
            "id",
            "user",
            "user_email",
            "user_display_name",
            "created_at",
            "last_seen_at",
            "expires_at",
            "revoked_at",
            "revocation_reason",
            "status_code",
            "status",
            "session_display_name",
            "authentication_method",
            "authentication_strength",
            "recent_auth_at",
            "created_ip",
            "last_ip",
            "user_agent",
        ]
        read_only_fields = fields

    def get_status_code(self, obj):
        return _session_status_code(obj)

    def get_status(self, obj):
        return _session_status_label(obj)

    def get_user_email(self, obj):
        return obj.user.email

    def get_user_display_name(self, obj):
        full_name = f"{obj.user.first_name} {obj.user.last_name}".strip()
        return full_name or obj.user.email

    def get_session_display_name(self, obj):
        return f"{obj.user.email} ({self.get_status(obj)})"

