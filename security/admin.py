"""Read-only Django admin for security audit data."""

from django.contrib import admin

from security.models import SecurityEvent
from user.models import AuthSession


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ["created_at", "event_type", "outcome", "severity", "user", "auth_session"]
    list_filter = ["event_type", "outcome", "severity", "created_at"]
    search_fields = ["user__email", "auth_session__id", "reason_code", "request_path"]
    readonly_fields = [
        "id",
        "created_at",
        "event_type",
        "outcome",
        "severity",
        "user",
        "auth_session",
        "ip_address",
        "user_agent",
        "request_method",
        "request_path",
        "reason_code",
        "metadata",
    ]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuthSession)
class AuthSessionAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "created_at", "expires_at", "revoked_at", "revocation_reason"]
    list_filter = ["revoked_at", "authentication_method", "authentication_strength"]
    search_fields = ["id", "user__email", "revocation_reason"]
    readonly_fields = [
        "id",
        "user",
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

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

