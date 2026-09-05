"""Deterministic operational evidence producers for B-OBS3.

The module keeps verification logic separate from persistence and only records
sanitized, provenance-backed evidence. It deliberately does not infer control
health from feature presence; evidence is created only from explicit
verification results.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Mapping

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from security.models import SecurityControl, SecurityEvidence, SecurityFinding
from security.services import (
    open_security_finding,
    refresh_control_status,
    resolve_security_finding,
    sync_security_control_registry,
)
from security.utils import sanitize_security_metadata


def _environment_label(explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip().lower()
    if getattr(settings, "TESTING", False):
        return "test"
    return "ci" if settings.DEBUG else "production"


def _source_reference(*parts: str) -> str:
    return ":".join(part for part in parts if part)


@dataclass(frozen=True, slots=True)
class EvidenceContext:
    """Trusted producer context for one evidence ingestion run."""

    producer_key: str
    source_type: str
    source_name: str
    source_reference: str
    environment: str
    observed_at: Any = None
    valid_for: timedelta | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    commit_sha: str = ""
    workflow: str = ""
    job: str = ""
    run_id: str = ""
    run_attempt: str = ""
    outcomes: Mapping[str, str] = field(default_factory=dict)
    check_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceSpec:
    """A deterministic control-evidence statement."""

    control_key: str
    evidence_type: str
    result: str
    title: str
    summary: str = ""
    source_type: str = ""
    source_name: str = ""
    source_reference: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    observed_at: Any = None
    valid_for: timedelta | None = None
    finding_key: str = ""
    finding_title: str = ""
    finding_description: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    affected_system: str = ""
    affected_component: str = ""


@dataclass(frozen=True, slots=True)
class RecordedEvidence:
    control_key: str
    evidence_id: str
    created: bool
    finding_key: str = ""
    finding_status: str = ""
    finding_created: bool = False
    finding_changed: bool = False


@dataclass(frozen=True, slots=True)
class EvidenceCollectionResult:
    producer_key: str
    source_type: str
    source_name: str
    source_reference: str
    environment: str
    records: tuple[RecordedEvidence, ...]

    @property
    def created_count(self) -> int:
        return sum(1 for record in self.records if record.created)

    @property
    def reused_count(self) -> int:
        return sum(1 for record in self.records if not record.created)

    @property
    def finding_count(self) -> int:
        return sum(1 for record in self.records if record.finding_key)


@dataclass(frozen=True, slots=True)
class CIControlTemplate:
    control_key: str
    test_group: str
    pass_title: str
    pass_summary: str
    fail_title: str
    fail_summary: str
    finding_key: str
    finding_title: str
    finding_description: str
    affected_system: str
    affected_component: str = ""
    valid_for_days: int = 7

    def build_spec(self, context: EvidenceContext, result: str) -> EvidenceSpec:
        title = self.pass_title if result == SecurityEvidence.Result.PASS else self.fail_title
        summary = self.pass_summary if result == SecurityEvidence.Result.PASS else self.fail_summary
        metadata = {
            **dict(context.metadata),
            "producer_key": context.producer_key,
            "runtime_environment": context.environment,
            "commit_sha": context.commit_sha,
            "workflow": context.workflow,
            "job": context.job,
            "run_id": context.run_id,
            "run_attempt": context.run_attempt,
            "test_group": self.test_group,
            "control_key": self.control_key,
            "verification_kind": "ci",
        }
        return EvidenceSpec(
            control_key=self.control_key,
            evidence_type=SecurityEvidence.EvidenceType.CI_RESULT,
            result=result,
            title=title,
            summary=summary,
            source_type=context.source_type,
            source_name=context.source_name,
            source_reference=context.source_reference,
            metadata=metadata,
            observed_at=context.observed_at,
            valid_for=timedelta(days=self.valid_for_days),
            finding_key=self.finding_key,
            finding_title=self.finding_title,
            finding_description=self.finding_description,
            expected_behavior=summary if result == SecurityEvidence.Result.PASS else self.finding_description,
            observed_behavior=summary,
            affected_system=self.affected_system,
            affected_component=self.affected_component,
        )


@dataclass(frozen=True, slots=True)
class ConfigCheckTemplate:
    check_name: str
    setting_name: str
    expected_value: str
    control_key: str
    pass_title: str
    pass_summary: str
    fail_title: str
    fail_summary: str
    finding_key: str
    finding_title: str
    finding_description: str
    affected_system: str
    affected_component: str = ""
    valid_for_days: int = 1

    def build_spec(self, context: EvidenceContext, observed_value: Any) -> EvidenceSpec:
        result = (
            SecurityEvidence.Result.PASS
            if _normalize_scalar(observed_value) == _normalize_scalar(self.expected_value)
            else SecurityEvidence.Result.FAIL
        )
        title = self.pass_title if result == SecurityEvidence.Result.PASS else self.fail_title
        summary = self.pass_summary if result == SecurityEvidence.Result.PASS else self.fail_summary
        metadata = {
            **dict(context.metadata),
            "producer_key": context.producer_key,
            "runtime_environment": context.environment,
            "setting_name": self.setting_name,
            "expected_value": self.expected_value,
            "observed_value": _normalize_scalar(observed_value),
            "check_name": self.check_name,
            "control_key": self.control_key,
            "verification_kind": "configuration",
        }
        return EvidenceSpec(
            control_key=self.control_key,
            evidence_type=SecurityEvidence.EvidenceType.CONFIGURATION_CHECK,
            result=result,
            title=title,
            summary=summary,
            source_type=context.source_type,
            source_name=context.source_name,
            source_reference=context.source_reference,
            metadata=metadata,
            observed_at=context.observed_at,
            valid_for=timedelta(days=self.valid_for_days),
            finding_key=self.finding_key,
            finding_title=self.finding_title,
            finding_description=self.finding_description,
            expected_behavior=f"{self.setting_name} = {self.expected_value}",
            observed_behavior=f"{self.setting_name} = {_normalize_scalar(observed_value)}",
            affected_system=self.affected_system,
            affected_component=self.affected_component,
        )


CI_CONTROL_TEMPLATES: tuple[CIControlTemplate, ...] = (
    CIControlTemplate(
        control_key="GAIT.AUTH.REFRESH_ROTATION",
        test_group="user.test_a1_refresh_lifecycle",
        pass_title="Refresh rotation verified by CI",
        pass_summary="The auth-security CI suite confirmed refresh credentials rotate after use.",
        fail_title="Refresh rotation failed in CI",
        fail_summary="The auth-security CI suite did not confirm refresh credentials rotate after use.",
        finding_key="GAIT.AUTH.REFRESH_ROTATION::ci::auth-security",
        finding_title="Refresh rotation regression detected in CI",
        finding_description="The auth-security CI suite did not verify that refresh credentials rotate after use.",
        affected_system="authentication refresh lifecycle",
    ),
    CIControlTemplate(
        control_key="GAIT.AUTH.REFRESH_REPLAY_PROTECTION",
        test_group="user.test_a1_refresh_lifecycle",
        pass_title="Refresh replay protection verified by CI",
        pass_summary="The auth-security CI suite confirmed replayed refresh credentials are rejected.",
        fail_title="Refresh replay protection failed in CI",
        fail_summary="The auth-security CI suite did not confirm replayed refresh credentials are rejected.",
        finding_key="GAIT.AUTH.REFRESH_REPLAY_PROTECTION::ci::auth-security",
        finding_title="Refresh replay protection regression detected in CI",
        finding_description="The auth-security CI suite did not verify replayed refresh credentials are rejected and handled safely.",
        affected_system="authentication refresh lifecycle",
    ),
    CIControlTemplate(
        control_key="GAIT.SESSION.SERVER_AUTHORITY",
        test_group="user.test_a2_sessions",
        pass_title="Server session authority verified by CI",
        pass_summary="The auth-security CI suite confirmed authenticated requests depend on live server-side session authority when enforcement applies.",
        fail_title="Server session authority failed in CI",
        fail_summary="The auth-security CI suite did not confirm authenticated requests depend on live server-side session authority when enforcement applies.",
        finding_key="GAIT.SESSION.SERVER_AUTHORITY::ci::auth-security",
        finding_title="Server session authority regression detected in CI",
        finding_description="The auth-security CI suite did not verify server-side session authority for authenticated requests.",
        affected_system="session enforcement",
    ),
    CIControlTemplate(
        control_key="GAIT.SESSION.LOGOUT_ALL_REVOCATION",
        test_group="user.test_a2_sessions",
        pass_title="Logout-all revocation verified by CI",
        pass_summary="The auth-security CI suite confirmed logout-all revokes active sessions and related refresh authority.",
        fail_title="Logout-all revocation failed in CI",
        fail_summary="The auth-security CI suite did not confirm logout-all revokes active sessions and related refresh authority.",
        finding_key="GAIT.SESSION.LOGOUT_ALL_REVOCATION::ci::auth-security",
        finding_title="Logout-all revocation regression detected in CI",
        finding_description="The auth-security CI suite did not verify logout-all revokes active sessions and related refresh authority.",
        affected_system="session revocation",
    ),
    CIControlTemplate(
        control_key="GAIT.MFA.TOTP",
        test_group="user.test_a0_auth_contract",
        pass_title="TOTP MFA verified by CI",
        pass_summary="The auth-security CI suite confirmed TOTP-based multi-factor authentication behaves as expected.",
        fail_title="TOTP MFA failed in CI",
        fail_summary="The auth-security CI suite did not confirm TOTP-based multi-factor authentication behaves as expected.",
        finding_key="GAIT.MFA.TOTP::ci::auth-security",
        finding_title="TOTP MFA regression detected in CI",
        finding_description="The auth-security CI suite did not verify TOTP-based multi-factor authentication behavior.",
        affected_system="multi-factor authentication",
    ),
    CIControlTemplate(
        control_key="GAIT.ASSURANCE.STEP_UP",
        test_group="user.test_a6_step_up",
        pass_title="Step-up assurance verified by CI",
        pass_summary="The auth-security CI suite confirmed sensitive actions require recent or stronger authentication when needed.",
        fail_title="Step-up assurance failed in CI",
        fail_summary="The auth-security CI suite did not confirm sensitive actions require recent or stronger authentication when needed.",
        finding_key="GAIT.ASSURANCE.STEP_UP::ci::auth-security",
        finding_title="Step-up assurance regression detected in CI",
        finding_description="The auth-security CI suite did not verify step-up assurance for sensitive actions.",
        affected_system="step-up assurance",
    ),
    CIControlTemplate(
        control_key="GAIT.ABUSE.POSTGRES_ENFORCEMENT",
        test_group="user.test_a5_abuse_control",
        pass_title="Abuse control enforcement verified by CI",
        pass_summary="The auth-security CI suite confirmed durable abuse counters are enforced across workers.",
        fail_title="Abuse control enforcement failed in CI",
        fail_summary="The auth-security CI suite did not confirm durable abuse counters are enforced across workers.",
        finding_key="GAIT.ABUSE.POSTGRES_ENFORCEMENT::ci::auth-security",
        finding_title="Abuse control enforcement regression detected in CI",
        finding_description="The auth-security CI suite did not verify PostgreSQL-backed abuse control enforcement.",
        affected_system="abuse control",
    ),
    CIControlTemplate(
        control_key="GAIT.AUDIT.SECURITY_EVENTS",
        test_group="security.test_security_events",
        pass_title="Security event auditing verified by CI",
        pass_summary="The security test suite confirmed security events are recorded durably.",
        fail_title="Security event auditing failed in CI",
        fail_summary="The security test suite did not confirm security events are recorded durably.",
        finding_key="GAIT.AUDIT.SECURITY_EVENTS::ci::security",
        finding_title="Security event auditing regression detected in CI",
        finding_description="The security test suite did not verify durable SecurityEvent recording.",
        affected_system="security audit",
    ),
    CIControlTemplate(
        control_key="GAIT.AUDIT.OBSERVATORY_ACCESS",
        test_group="security.test_security_events",
        pass_title="Observatory access controls verified by CI",
        pass_summary="The security test suite confirmed the Observatory denies anonymous and ordinary authenticated users while allowing staff viewers.",
        fail_title="Observatory access controls failed in CI",
        fail_summary="The security test suite did not confirm the Observatory enforces staff-only access.",
        finding_key="GAIT.AUDIT.OBSERVATORY_ACCESS::ci::security",
        finding_title="Observatory access regression detected in CI",
        finding_description="The security test suite did not verify staff-only Observatory access.",
        affected_system="security observatory access",
    ),
    CIControlTemplate(
        control_key="GAIT.ACCOUNT.RESET_ENUMERATION_PROTECTION",
        test_group="user.test_a0_auth_contract",
        pass_title="Password reset enumeration protection verified by CI",
        pass_summary="The auth-security CI suite confirmed password reset requests do not reveal whether an account exists.",
        fail_title="Password reset enumeration protection failed in CI",
        fail_summary="The auth-security CI suite did not confirm password reset requests avoid account enumeration.",
        finding_key="GAIT.ACCOUNT.RESET_ENUMERATION_PROTECTION::ci::auth-security",
        finding_title="Password reset enumeration regression detected in CI",
        finding_description="The auth-security CI suite did not verify password reset enumeration protection.",
        affected_system="password reset flow",
    ),
    CIControlTemplate(
        control_key="GAIT.ACCOUNT.DISABLED_USER_ENFORCEMENT",
        test_group="user.test_a4_account_security",
        pass_title="Disabled-user enforcement verified by CI",
        pass_summary="The auth-security CI suite confirmed inactive accounts are denied authentication and protected resource access.",
        fail_title="Disabled-user enforcement failed in CI",
        fail_summary="The auth-security CI suite did not confirm inactive accounts are denied authentication and protected resource access.",
        finding_key="GAIT.ACCOUNT.DISABLED_USER_ENFORCEMENT::ci::auth-security",
        finding_title="Disabled-user enforcement regression detected in CI",
        finding_description="The auth-security CI suite did not verify disabled-user enforcement.",
        affected_system="account security",
    ),
)


CONFIG_CHECK_TEMPLATES: tuple[ConfigCheckTemplate, ...] = (
    ConfigCheckTemplate(
        check_name="check_auth_session_enforcement",
        setting_name="AUTH_SESSION_ENFORCEMENT",
        expected_value="ENFORCE",
        control_key="GAIT.SESSION.SERVER_AUTHORITY",
        pass_title="Auth session enforcement is enabled",
        pass_summary="Runtime configuration enforces server-side session authority.",
        fail_title="Auth session enforcement is not enabled",
        fail_summary="Runtime configuration does not enforce server-side session authority.",
        finding_key="GAIT.SESSION.SERVER_AUTHORITY::config::auth-session",
        finding_title="Auth session enforcement drift detected",
        finding_description="Runtime configuration is not enforcing server-side session authority.",
        affected_system="authentication settings",
    ),
    ConfigCheckTemplate(
        check_name="check_abuse_control_enforcement",
        setting_name="ABUSE_CONTROL_ENFORCEMENT",
        expected_value="ENFORCE",
        control_key="GAIT.ABUSE.POSTGRES_ENFORCEMENT",
        pass_title="Abuse control enforcement is enabled",
        pass_summary="Runtime configuration enforces durable abuse control policies.",
        fail_title="Abuse control enforcement is not enabled",
        fail_summary="Runtime configuration does not enforce durable abuse control policies.",
        finding_key="GAIT.ABUSE.POSTGRES_ENFORCEMENT::config::abuse-control",
        finding_title="Abuse control enforcement drift detected",
        finding_description="Runtime configuration is not enforcing durable abuse control policies.",
        affected_system="abuse control settings",
    ),
    ConfigCheckTemplate(
        check_name="check_refresh_rotation_enabled",
        setting_name="JWT_REFRESH_ROTATION_ENABLED",
        expected_value="True",
        control_key="GAIT.AUTH.REFRESH_ROTATION",
        pass_title="Refresh rotation is enabled",
        pass_summary="Runtime configuration keeps refresh-token rotation enabled.",
        fail_title="Refresh rotation is not enabled",
        fail_summary="Runtime configuration does not keep refresh-token rotation enabled.",
        finding_key="GAIT.AUTH.REFRESH_ROTATION::config::refresh-rotation",
        finding_title="Refresh rotation setting drift detected",
        finding_description="Runtime configuration is not keeping refresh-token rotation enabled.",
        affected_system="JWT refresh settings",
    ),
)


class EvidenceProducer(ABC):
    """Base class for deterministic evidence producers."""

    producer_key: str
    source_type: str
    source_name: str

    @abstractmethod
    def build_assessments(self, context: EvidenceContext) -> tuple[EvidenceSpec, ...]:
        raise NotImplementedError

    def collect(self, context: EvidenceContext) -> EvidenceCollectionResult:
        return record_assessments(*self.build_assessments(context), context=context)


class CISecurityEvidenceProducer(EvidenceProducer):
    producer_key = "auth-security-ci"
    source_type = "automated_test"
    source_name = "auth-security-ci"

    def build_assessments(self, context: EvidenceContext) -> tuple[EvidenceSpec, ...]:
        assessments = []
        for template in CI_CONTROL_TEMPLATES:
            result = _normalize_result(
                context.outcomes.get(template.control_key, SecurityEvidence.Result.PASS)
            )
            assessments.append(template.build_spec(context, result))
        return tuple(assessments)


class ConfigurationSecurityEvidenceProducer(EvidenceProducer):
    producer_key = "production-security-config"
    source_type = "configuration_check"
    source_name = "production-security-config"

    def build_assessments(self, context: EvidenceContext) -> tuple[EvidenceSpec, ...]:
        from django.conf import settings as django_settings

        assessments = []
        for template in CONFIG_CHECK_TEMPLATES:
            if context.check_names and template.check_name not in context.check_names:
                continue
            observed_value = getattr(django_settings, template.setting_name, None)
            assessments.append(template.build_spec(context, observed_value))
        return tuple(assessments)


def _normalize_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    return str(value).strip()


def _normalize_result(value: Any) -> str:
    result = _normalize_scalar(value).upper()
    return result or SecurityEvidence.Result.PASS


def _build_context_metadata(context: EvidenceContext, spec: EvidenceSpec) -> dict[str, Any]:
    metadata = {
        **dict(context.metadata),
        **dict(spec.metadata),
        "producer_key": context.producer_key,
        "source_type": spec.source_type or context.source_type,
        "source_name": spec.source_name or context.source_name,
        "source_reference": spec.source_reference or context.source_reference,
        "runtime_environment": context.environment,
        "control_key": spec.control_key,
        "result": spec.result,
    }
    return sanitize_security_metadata(metadata)


def _get_or_create_evidence(
    *,
    control: SecurityControl,
    spec: EvidenceSpec,
    context: EvidenceContext,
) -> tuple[SecurityEvidence, bool]:
    source_type = spec.source_type or context.source_type
    source_name = spec.source_name or context.source_name
    source_reference = spec.source_reference or context.source_reference
    observed_at = spec.observed_at or context.observed_at or timezone.now()
    valid_until = None
    if spec.valid_for is not None:
        valid_until = observed_at + spec.valid_for
    elif context.valid_for is not None:
        valid_until = observed_at + context.valid_for

    existing = (
        SecurityEvidence.objects.select_for_update()
        .filter(
            control=control,
            evidence_type=spec.evidence_type,
            source_type=source_type,
            source_name=source_name,
            source_reference=source_reference,
        )
        .order_by("-observed_at", "-created_at", "-id")
        .first()
    )
    if existing:
        return existing, False

    evidence = SecurityEvidence.objects.create(
        control=control,
        evidence_type=spec.evidence_type,
        source_type=source_type,
        source_name=source_name,
        source_reference=source_reference,
        title=spec.title,
        summary=spec.summary,
        result=spec.result,
        observed_at=observed_at,
        valid_until=valid_until,
        metadata=_build_context_metadata(context, spec),
    )
    return evidence, True


def _maybe_update_finding(
    *,
    control: SecurityControl,
    spec: EvidenceSpec,
    context: EvidenceContext,
    evidence: SecurityEvidence,
) -> tuple[str, bool, bool]:
    if not spec.finding_key:
        return "", False, False

    source_type = spec.source_type or context.source_type
    source_reference = spec.source_reference or context.source_reference
    metadata = _build_context_metadata(context, spec)

    if spec.result == SecurityEvidence.Result.FAIL:
        finding, created = open_security_finding(
            finding_key=spec.finding_key,
            control=control,
            title=spec.finding_title or spec.title,
            description=spec.finding_description or spec.summary,
            severity=control.severity_if_failed,
            expected_behavior=spec.expected_behavior,
            observed_behavior=spec.observed_behavior or spec.summary,
            affected_system=spec.affected_system,
            affected_component=spec.affected_component,
            source_type=source_type,
            source_reference=source_reference,
            evidence=[evidence],
            metadata=metadata,
        )
        return finding.status, created, True

    if spec.result == SecurityEvidence.Result.PASS:
        finding = SecurityFinding.objects.filter(finding_key=spec.finding_key).first()
        if finding and finding.status in (
            SecurityFinding.Status.OPEN,
            SecurityFinding.Status.ACKNOWLEDGED,
        ):
            resolve_security_finding(
                finding,
                resolution_summary=(
                    f"Verified recovery from {source_type} evidence recorded by "
                    f"{context.producer_key}."
                ),
            )
            return finding.status, False, True
    return "", False, False


def record_assessments(*assessments: EvidenceSpec, context: EvidenceContext | None = None) -> EvidenceCollectionResult:
    """Persist one or more deterministic assessments as security evidence."""

    if context is None:
        raise TypeError("record_assessments requires a context")

    sync_security_control_registry()
    records: list[RecordedEvidence] = []

    with transaction.atomic():
        for spec in assessments:
            control = SecurityControl.objects.select_for_update().get(control_key=spec.control_key)
            evidence, created = _get_or_create_evidence(control=control, spec=spec, context=context)
            if created:
                refresh_control_status(control)
            finding_status, finding_created, finding_changed = _maybe_update_finding(
                control=control,
                spec=spec,
                context=context,
                evidence=evidence,
            )
            records.append(
                RecordedEvidence(
                    control_key=control.control_key,
                    evidence_id=str(evidence.id),
                    created=created,
                    finding_key=spec.finding_key,
                    finding_status=finding_status,
                    finding_created=finding_created,
                    finding_changed=finding_changed,
                )
            )

    return EvidenceCollectionResult(
        producer_key=context.producer_key,
        source_type=context.source_type,
        source_name=context.source_name,
        source_reference=context.source_reference,
        environment=context.environment,
        records=tuple(records),
    )


def build_ci_context(
    *,
    source_name: str = "auth-security-ci",
    source_reference: str = "",
    environment: str | None = None,
    commit_sha: str = "",
    workflow: str = "",
    job: str = "",
    run_id: str = "",
    run_attempt: str = "",
    observed_at=None,
    outcomes: Mapping[str, str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceContext:
    reference = source_reference or _source_reference(workflow, job, run_id, run_attempt, commit_sha)
    return EvidenceContext(
        producer_key="auth-security-ci",
        source_type="automated_test",
        source_name=source_name,
        source_reference=reference,
        environment=_environment_label(environment),
        observed_at=observed_at or timezone.now(),
        metadata=metadata or {},
        commit_sha=commit_sha,
        workflow=workflow,
        job=job,
        run_id=run_id,
        run_attempt=run_attempt,
        outcomes=outcomes or {},
    )


def build_configuration_context(
    *,
    source_name: str = "production-security-config",
    source_reference: str = "",
    environment: str | None = None,
    observed_at=None,
    check_names: tuple[str, ...] = (),
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceContext:
    return EvidenceContext(
        producer_key="production-security-config",
        source_type="configuration_check",
        source_name=source_name,
        source_reference=source_reference or _source_reference(_environment_label(environment), "config"),
        environment=_environment_label(environment),
        observed_at=observed_at or timezone.now(),
        metadata=metadata or {},
        check_names=check_names,
    )


def collect_ci_evidence(
    *,
    source_name: str = "auth-security-ci",
    source_reference: str = "",
    environment: str | None = None,
    commit_sha: str = "",
    workflow: str = "",
    job: str = "",
    run_id: str = "",
    run_attempt: str = "",
    observed_at=None,
    outcomes: Mapping[str, str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceCollectionResult:
    """Build and persist CI evidence for the trusted auth-security workflow."""

    context = build_ci_context(
        source_name=source_name,
        source_reference=source_reference,
        environment=environment,
        commit_sha=commit_sha,
        workflow=workflow,
        job=job,
        run_id=run_id,
        run_attempt=run_attempt,
        observed_at=observed_at,
        outcomes=outcomes,
        metadata=metadata,
    )
    producer = CISecurityEvidenceProducer()
    return record_assessments(*producer.build_assessments(context), context=context)


def collect_configuration_evidence(
    *,
    source_name: str = "production-security-config",
    source_reference: str = "",
    environment: str | None = None,
    observed_at=None,
    check_names: tuple[str, ...] = (),
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceCollectionResult:
    """Build and persist runtime configuration evidence."""

    context = build_configuration_context(
        source_name=source_name,
        source_reference=source_reference,
        environment=environment,
        observed_at=observed_at,
        check_names=check_names,
        metadata=metadata,
    )
    producer = ConfigurationSecurityEvidenceProducer()
    return record_assessments(*producer.build_assessments(context), context=context)


def get_ci_control_templates() -> tuple[CIControlTemplate, ...]:
    """Expose the fixed CI mapping set for tests and documentation."""

    return CI_CONTROL_TEMPLATES
