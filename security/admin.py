"""Read-only Django admin for security audit data."""

from django.contrib import admin

from security.models import SecurityControl, SecurityEvent, SecurityEvidence, SecurityFinding
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


@admin.register(SecurityControl)
class SecurityControlAdmin(admin.ModelAdmin):
    list_display = ["control_key", "domain", "control_type", "lifecycle", "status", "severity_if_failed"]
    list_filter = ["domain", "control_type", "lifecycle", "status", "severity_if_failed"]
    search_fields = ["control_key", "title", "description"]
    readonly_fields = [
        "id",
        "control_key",
        "domain",
        "title",
        "description",
        "control_type",
        "lifecycle",
        "severity_if_failed",
        "created_at",
        "updated_at",
    ]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SecurityEvidence)
class SecurityEvidenceAdmin(admin.ModelAdmin):
    list_display = ["observed_at", "control", "evidence_type", "result", "source_type", "source_name"]
    list_filter = ["evidence_type", "result", "source_type", "observed_at"]
    search_fields = ["control__control_key", "title", "summary", "source_name", "source_reference"]
    readonly_fields = [field.name for field in SecurityEvidence._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SecurityFinding)
class SecurityFindingAdmin(admin.ModelAdmin):
    list_display = ["finding_key", "control", "severity", "status", "last_seen_at", "resolved_at"]
    list_filter = ["status", "severity", "control__domain", "last_seen_at"]
    search_fields = ["finding_key", "title", "description", "affected_system", "affected_component"]
    readonly_fields = [
        "id",
        "finding_key",
        "control",
        "severity",
        "title",
        "description",
        "expected_behavior",
        "observed_behavior",
        "affected_system",
        "affected_component",
        "source_type",
        "source_reference",
        "first_seen_at",
        "last_seen_at",
        "metadata",
        "created_at",
        "updated_at",
    ]
    filter_horizontal = ["evidence", "related_events"]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

