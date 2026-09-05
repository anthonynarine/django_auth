"""Serializers for security audit reads."""

from __future__ import annotations

from django.utils import timezone
from rest_framework import serializers

from security.models import SecurityControl, SecurityEvent, SecurityEvidence, SecurityFinding
from security.presentation import describe_security_event, describe_session_state
from security.utils import humanize_code
from user.models import AuthSession


def _session_status_code(session: AuthSession) -> str:
    return describe_session_state(session)["status_code"]


def _session_status_label(session: AuthSession) -> str:
    return describe_session_state(session)["status"]


class SecurityEventSerializer(serializers.ModelSerializer):
    event_label = serializers.SerializerMethodField()
    outcome_label = serializers.SerializerMethodField()
    severity_label = serializers.SerializerMethodField()
    title = serializers.SerializerMethodField()
    description = serializers.SerializerMethodField()
    category = serializers.SerializerMethodField()
    category_label = serializers.SerializerMethodField()
    system_response = serializers.SerializerMethodField()
    impact_summary = serializers.SerializerMethodField()
    recommended_action = serializers.SerializerMethodField()
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
            "title",
            "description",
            "category",
            "category_label",
            "system_response",
            "impact_summary",
            "recommended_action",
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

    def _presentation(self, obj):
        cache = getattr(self, "_presentation_cache", None)
        if cache is None:
            cache = {}
            self._presentation_cache = cache
        key = str(obj.pk or id(obj))
        if key not in cache:
            cache[key] = describe_security_event(obj)
        return cache[key]

    def get_event_label(self, obj):
        return obj.get_event_type_display()

    def get_outcome_label(self, obj):
        return obj.get_outcome_display()

    def get_severity_label(self, obj):
        return self._presentation(obj).severity_label

    def get_title(self, obj):
        return self._presentation(obj).title

    def get_description(self, obj):
        return self._presentation(obj).description

    def get_category(self, obj):
        return self._presentation(obj).category

    def get_category_label(self, obj):
        return self._presentation(obj).category_label

    def get_system_response(self, obj):
        return self._presentation(obj).system_response

    def get_impact_summary(self, obj):
        return self._presentation(obj).impact_summary

    def get_recommended_action(self, obj):
        return self._presentation(obj).recommended_action

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
    status_description = serializers.SerializerMethodField()
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
            "status_description",
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

    def get_status_description(self, obj):
        return describe_session_state(obj)["status_description"]

    def get_user_email(self, obj):
        return obj.user.email

    def get_user_display_name(self, obj):
        full_name = f"{obj.user.first_name} {obj.user.last_name}".strip()
        return full_name or obj.user.email

    def get_session_display_name(self, obj):
        return f"{obj.user.email} ({self.get_status(obj)})"


class SecurityControlSerializer(serializers.ModelSerializer):
    domain_label = serializers.CharField(source="get_domain_display", read_only=True)
    control_type_label = serializers.CharField(source="get_control_type_display", read_only=True)
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    lifecycle_label = serializers.CharField(source="get_lifecycle_display", read_only=True)
    severity_if_failed_label = serializers.SerializerMethodField()

    class Meta:
        model = SecurityControl
        fields = [
            "id",
            "control_key",
            "domain",
            "domain_label",
            "title",
            "description",
            "control_type",
            "control_type_label",
            "lifecycle",
            "lifecycle_label",
            "status",
            "status_label",
            "status_reason",
            "severity_if_failed",
            "severity_if_failed_label",
            "last_evaluated_at",
            "last_evidence_at",
            "next_review_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_severity_if_failed_label(self, obj):
        return humanize_code(obj.severity_if_failed)


class SecurityEvidenceSerializer(serializers.ModelSerializer):
    control_key = serializers.CharField(source="control.control_key", read_only=True)
    control_title = serializers.CharField(source="control.title", read_only=True)
    domain = serializers.CharField(source="control.domain", read_only=True)
    domain_label = serializers.CharField(source="control.get_domain_display", read_only=True)
    evidence_type_label = serializers.CharField(source="get_evidence_type_display", read_only=True)
    result_label = serializers.CharField(source="get_result_display", read_only=True)
    is_stale = serializers.SerializerMethodField()

    class Meta:
        model = SecurityEvidence
        fields = [
            "id",
            "control",
            "control_key",
            "control_title",
            "domain",
            "domain_label",
            "evidence_type",
            "evidence_type_label",
            "source_type",
            "source_name",
            "source_reference",
            "title",
            "summary",
            "result",
            "result_label",
            "observed_at",
            "valid_until",
            "is_stale",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields

    def get_is_stale(self, obj):
        return bool(obj.valid_until and obj.valid_until <= timezone.now())


class SecurityFindingSerializer(serializers.ModelSerializer):
    control_key = serializers.CharField(source="control.control_key", read_only=True)
    control_title = serializers.CharField(source="control.title", read_only=True)
    domain = serializers.CharField(source="control.domain", read_only=True)
    domain_label = serializers.CharField(source="control.get_domain_display", read_only=True)
    severity_label = serializers.SerializerMethodField()
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    evidence_ids = serializers.SerializerMethodField()
    related_event_ids = serializers.SerializerMethodField()

    class Meta:
        model = SecurityFinding
        fields = [
            "id",
            "finding_key",
            "control",
            "control_key",
            "control_title",
            "domain",
            "domain_label",
            "severity",
            "severity_label",
            "status",
            "status_label",
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
            "resolved_at",
            "resolution_summary",
            "metadata",
            "evidence_ids",
            "related_event_ids",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_severity_label(self, obj):
        return humanize_code(obj.severity)

    def get_evidence_ids(self, obj):
        return [str(evidence.id) for evidence in list(obj.evidence.all())[:20]]

    def get_related_event_ids(self, obj):
        return [str(event.id) for event in list(obj.related_events.all())[:20]]


class SecurityControlDetailSerializer(SecurityControlSerializer):
    recent_evidence = serializers.SerializerMethodField()
    open_findings = serializers.SerializerMethodField()

    class Meta(SecurityControlSerializer.Meta):
        fields = SecurityControlSerializer.Meta.fields + ["recent_evidence", "open_findings"]

    def get_recent_evidence(self, obj):
        queryset = obj.evidence.order_by("-observed_at", "-created_at", "-id")[:10]
        return SecurityEvidenceSerializer(queryset, many=True).data

    def get_open_findings(self, obj):
        queryset = obj.findings.exclude(
            status__in=[
                SecurityFinding.Status.RESOLVED,
                SecurityFinding.Status.ACCEPTED_RISK,
                SecurityFinding.Status.FALSE_POSITIVE,
            ]
        ).order_by("-last_seen_at", "-created_at", "-id")[:10]
        return SecurityFindingSerializer(queryset, many=True).data

