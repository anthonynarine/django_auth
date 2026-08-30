"""Serializers for security audit reads."""

from __future__ import annotations

from rest_framework import serializers

from security.models import SecurityEvent
from user.models import AuthSession


class SecurityEventSerializer(serializers.ModelSerializer):
    user_email = serializers.SerializerMethodField()
    session_user_email = serializers.SerializerMethodField()

    class Meta:
        model = SecurityEvent
        fields = [
            "id",
            "created_at",
            "event_type",
            "outcome",
            "severity",
            "user",
            "user_email",
            "auth_session",
            "session_user_email",
            "ip_address",
            "user_agent",
            "request_method",
            "request_path",
            "reason_code",
            "metadata",
        ]
        read_only_fields = fields

    def get_user_email(self, obj):
        return obj.user.email if obj.user else None

    def get_session_user_email(self, obj):
        return obj.auth_session.user.email if obj.auth_session else None


class AuthSessionSerializer(serializers.ModelSerializer):
    user_email = serializers.SerializerMethodField()

    class Meta:
        model = AuthSession
        fields = [
            "id",
            "user",
            "user_email",
            "created_at",
            "last_seen_at",
            "expires_at",
            "revoked_at",
            "revocation_reason",
            "authentication_method",
            "authentication_strength",
            "recent_auth_at",
            "created_ip",
            "last_ip",
            "user_agent",
        ]
        read_only_fields = fields

    def get_user_email(self, obj):
        return obj.user.email

