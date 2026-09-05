from __future__ import annotations

import io
import threading
from datetime import timedelta
from unittest.mock import patch

from django.core.management import call_command
from django.db import connection, close_old_connections
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from security.models import SecurityControl, SecurityEvidence, SecurityFinding
from security.operational_evidence import (
    CI_CONTROL_TEMPLATES,
    EvidenceContext,
    EvidenceSpec,
    build_ci_context,
    build_configuration_context,
    collect_ci_evidence,
    collect_configuration_evidence,
    get_ci_control_templates,
    record_assessments,
)
from security.services import sync_security_control_registry


class OperationalEvidenceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        sync_security_control_registry()

    def setUp(self):
        self.refresh_rotation = SecurityControl.objects.get(
            control_key="GAIT.AUTH.REFRESH_ROTATION"
        )
        self.refresh_replay = SecurityControl.objects.get(
            control_key="GAIT.AUTH.REFRESH_REPLAY_PROTECTION"
        )
        self.session_authority = SecurityControl.objects.get(
            control_key="GAIT.SESSION.SERVER_AUTHORITY"
        )
        self.logout_all = SecurityControl.objects.get(
            control_key="GAIT.SESSION.LOGOUT_ALL_REVOCATION"
        )
        self.step_up = SecurityControl.objects.get(control_key="GAIT.ASSURANCE.STEP_UP")
        self.abuse = SecurityControl.objects.get(control_key="GAIT.ABUSE.POSTGRES_ENFORCEMENT")
        self.security_events = SecurityControl.objects.get(control_key="GAIT.AUDIT.SECURITY_EVENTS")

    def test_ci_pass_creates_evidence_for_all_mapped_controls(self):
        result = collect_ci_evidence(
            source_reference="auth-security-ci:run-1",
            environment="ci",
            commit_sha="abc123",
            workflow="auth-security-ci",
            job="sqlite-auth-regression",
            run_id="101",
            run_attempt="1",
        )

        self.assertEqual(result.environment, "ci")
        self.assertEqual(result.created_count, len(CI_CONTROL_TEMPLATES))
        self.assertEqual(SecurityEvidence.objects.count(), len(CI_CONTROL_TEMPLATES))
        self.refresh_rotation.refresh_from_db()
        self.assertEqual(self.refresh_rotation.status, SecurityControl.Status.HEALTHY)

        evidence = SecurityEvidence.objects.get(control=self.refresh_rotation)
        self.assertEqual(evidence.result, SecurityEvidence.Result.PASS)
        self.assertEqual(evidence.evidence_type, SecurityEvidence.EvidenceType.CI_RESULT)
        self.assertEqual(evidence.source_type, "automated_test")
        self.assertEqual(evidence.source_name, "auth-security-ci")
        self.assertEqual(evidence.source_reference, "auth-security-ci:run-1")
        self.assertEqual(evidence.metadata["runtime_environment"], "ci")
        self.assertEqual(evidence.metadata["workflow"], "auth-security-ci")
        self.assertEqual(evidence.metadata["job"], "sqlite-auth-regression")

    def test_duplicate_same_ci_run_dedupes_evidence(self):
        first = collect_ci_evidence(
            source_reference="auth-security-ci:run-duplicate",
            environment="ci",
            workflow="auth-security-ci",
            job="sqlite-auth-regression",
            run_id="102",
            run_attempt="1",
        )
        second = collect_ci_evidence(
            source_reference="auth-security-ci:run-duplicate",
            environment="ci",
            workflow="auth-security-ci",
            job="sqlite-auth-regression",
            run_id="102",
            run_attempt="1",
        )

        self.assertTrue(all(record.created for record in first.records))
        self.assertTrue(all(not record.created for record in second.records))
        self.assertEqual(
            SecurityEvidence.objects.filter(control=self.refresh_rotation).count(),
            1,
        )
        self.assertEqual(SecurityEvidence.objects.count(), len(CI_CONTROL_TEMPLATES))

    def test_different_ci_runs_append_evidence(self):
        collect_ci_evidence(
            source_reference="auth-security-ci:run-a",
            environment="ci",
            workflow="auth-security-ci",
            job="sqlite-auth-regression",
            run_id="103",
            run_attempt="1",
        )
        collect_ci_evidence(
            source_reference="auth-security-ci:run-b",
            environment="ci",
            workflow="auth-security-ci",
            job="sqlite-auth-regression",
            run_id="104",
            run_attempt="1",
        )

        self.assertEqual(
            SecurityEvidence.objects.filter(control=self.refresh_rotation).count(),
            2,
        )
        self.assertEqual(SecurityEvidence.objects.count(), len(CI_CONTROL_TEMPLATES) * 2)

    def test_fail_evidence_opens_finding_and_recovery_resolves_it(self):
        fail_context = build_ci_context(
            source_reference="auth-security-ci:fail-1",
            environment="ci",
            workflow="auth-security-ci",
            job="sqlite-auth-regression",
            run_id="105",
            run_attempt="1",
            outcomes={
                "GAIT.AUTH.REFRESH_REPLAY_PROTECTION": SecurityEvidence.Result.FAIL,
            },
        )
        fail_result = collect_ci_evidence(
            source_reference=fail_context.source_reference,
            environment=fail_context.environment,
            workflow=fail_context.workflow,
            job=fail_context.job,
            run_id=fail_context.run_id,
            run_attempt=fail_context.run_attempt,
            outcomes=fail_context.outcomes,
        )

        replay_evidence = SecurityEvidence.objects.get(control=self.refresh_replay)
        self.assertEqual(replay_evidence.result, SecurityEvidence.Result.FAIL)
        self.refresh_replay.refresh_from_db()
        self.assertEqual(self.refresh_replay.status, SecurityControl.Status.CONTROL_FAILURE)
        finding = SecurityFinding.objects.get(
            finding_key="GAIT.AUTH.REFRESH_REPLAY_PROTECTION::ci::auth-security"
        )
        self.assertEqual(finding.status, SecurityFinding.Status.OPEN)
        self.assertEqual(finding.evidence.count(), 1)
        first_seen = finding.last_seen_at

        repeat_fail = collect_ci_evidence(
            source_reference=fail_context.source_reference,
            environment=fail_context.environment,
            workflow=fail_context.workflow,
            job=fail_context.job,
            run_id=fail_context.run_id,
            run_attempt=fail_context.run_attempt,
            outcomes=fail_context.outcomes,
        )
        finding.refresh_from_db()
        self.assertEqual(SecurityEvidence.objects.filter(control=self.refresh_replay).count(), 1)
        self.assertEqual(SecurityFinding.objects.filter(
            finding_key="GAIT.AUTH.REFRESH_REPLAY_PROTECTION::ci::auth-security"
        ).count(), 1)
        self.assertGreaterEqual(finding.last_seen_at, first_seen)
        self.assertFalse(repeat_fail.records[1].created)

        pass_result = collect_ci_evidence(
            source_reference="auth-security-ci:recovery-1",
            environment="ci",
            workflow="auth-security-ci",
            job="sqlite-auth-regression",
            run_id="106",
            run_attempt="1",
        )
        finding.refresh_from_db()
        self.refresh_replay.refresh_from_db()
        self.assertEqual(self.refresh_replay.status, SecurityControl.Status.HEALTHY)
        self.assertEqual(finding.status, SecurityFinding.Status.RESOLVED)
        self.assertIsNotNone(finding.resolved_at)
        self.assertTrue(pass_result.records[1].created)
        self.assertEqual(pass_result.records[1].finding_key, "GAIT.AUTH.REFRESH_REPLAY_PROTECTION::ci::auth-security")

    def test_expired_pass_reduces_control_to_needs_attention(self):
        observed_at = timezone.now() - timedelta(days=2)
        spec = EvidenceSpec(
            control_key="GAIT.AUTH.REFRESH_ROTATION",
            evidence_type=SecurityEvidence.EvidenceType.CI_RESULT,
            result=SecurityEvidence.Result.PASS,
            title="Refresh rotation verified",
            summary="Historical CI evidence confirmed refresh rotation.",
            source_type="automated_test",
            source_name="auth-security-ci",
            source_reference="auth-security-ci:expired",
            observed_at=observed_at,
            valid_for=timedelta(days=1),
            metadata={"runtime_environment": "ci"},
            finding_key="GAIT.AUTH.REFRESH_ROTATION::ci::auth-security",
            finding_title="Refresh rotation regression detected in CI",
            finding_description="The auth-security CI suite did not verify that refresh credentials rotate after use.",
            expected_behavior="Refresh credentials rotate after use.",
            observed_behavior="Refresh credentials rotated after use.",
            affected_system="authentication refresh lifecycle",
        )
        record_assessments(spec, context=build_ci_context(source_reference="auth-security-ci:expired", environment="ci"))

        self.refresh_rotation.refresh_from_db()
        evidence = SecurityEvidence.objects.get(control=self.refresh_rotation)
        self.assertTrue(evidence.valid_until < timezone.now())
        self.assertEqual(self.refresh_rotation.status, SecurityControl.Status.NEEDS_ATTENTION)

    def test_warning_and_informational_results_do_not_prove_health(self):
        warning_spec = EvidenceSpec(
            control_key="GAIT.AUDIT.SECURITY_EVENTS",
            evidence_type=SecurityEvidence.EvidenceType.CONFIGURATION_CHECK,
            result=SecurityEvidence.Result.WARNING,
            title="Security event auditing needs review",
            summary="The audit pipeline should be reviewed.",
            source_type="configuration_check",
            source_name="production-security-config",
            source_reference="production:warning",
            metadata={"runtime_environment": "production"},
            finding_key="GAIT.AUDIT.SECURITY_EVENTS::config::review",
            finding_title="Security event audit review needed",
            finding_description="The audit pipeline requires follow-up.",
            expected_behavior="Security events are durably recorded.",
            observed_behavior="Audit coverage is not fully established.",
            affected_system="security audit",
        )
        record_assessments(warning_spec, context=build_configuration_context(environment="production"))
        self.security_events.refresh_from_db()
        self.assertEqual(self.security_events.status, SecurityControl.Status.NEEDS_ATTENTION)

        informational_spec = EvidenceSpec(
            control_key="GAIT.SESSION.LOGOUT_ALL_REVOCATION",
            evidence_type=SecurityEvidence.EvidenceType.SECURITY_EVENT,
            result=SecurityEvidence.Result.INFORMATIONAL,
            title="Logout-all observation recorded",
            summary="A logout-all related event was observed.",
            source_type="security_event",
            source_name="manual-observation",
            source_reference="obs-1",
            metadata={"runtime_environment": "test"},
        )
        record_assessments(informational_spec, context=build_ci_context(source_reference="obs-1", environment="test"))
        self.logout_all.refresh_from_db()
        self.assertEqual(self.logout_all.status, SecurityControl.Status.UNKNOWN)

    def test_secret_metadata_is_sanitized_for_evidence_and_findings(self):
        spec = EvidenceSpec(
            control_key="GAIT.AUDIT.SECURITY_EVENTS",
            evidence_type=SecurityEvidence.EvidenceType.CI_RESULT,
            result=SecurityEvidence.Result.FAIL,
            title="Security event auditing failed",
            summary="The audit pipeline did not verify durability.",
            source_type="automated_test",
            source_name="auth-security-ci",
            source_reference="auth-security-ci:sensitive",
            metadata={
                "password": "secret-password",
                "otp": "123456",
                "token": "token-value",
                "refresh_token": "refresh-value",
                "authorization": "Bearer token",
                "private_key": "private-key",
                "secret": "top-secret",
                "api_key": "api-key",
                "patient_name": "Jane Doe",
                "patient_id": "P-123",
                "mrn": "MRN-1",
                "dob": "2000-01-01",
                "diagnosis": "example",
                "phi": "protected",
            },
            finding_key="GAIT.AUDIT.SECURITY_EVENTS::ci::sensitive",
            finding_title="Sensitive audit failure",
            finding_description="Audit verification failed.",
            expected_behavior="Security events are durably recorded.",
            observed_behavior="The audit pipeline did not verify durability.",
            affected_system="security audit",
        )
        record_assessments(spec, context=build_ci_context(source_reference="auth-security-ci:sensitive", environment="ci"))

        evidence = SecurityEvidence.objects.get(control=self.security_events)
        finding = SecurityFinding.objects.get(finding_key="GAIT.AUDIT.SECURITY_EVENTS::ci::sensitive")
        for payload in (evidence.metadata, finding.metadata):
            self.assertEqual(payload["password"], "[REDACTED]")
            self.assertEqual(payload["otp"], "[REDACTED]")
            self.assertEqual(payload["token"], "[REDACTED]")
            self.assertEqual(payload["refresh_token"], "[REDACTED]")
            self.assertEqual(payload["authorization"], "[REDACTED]")
            self.assertEqual(payload["private_key"], "[REDACTED]")
            self.assertEqual(payload["secret"], "[REDACTED]")
            self.assertEqual(payload["api_key"], "[REDACTED]")
            self.assertEqual(payload["patient_name"], "[REDACTED]")
            self.assertEqual(payload["patient_id"], "[REDACTED]")
            self.assertEqual(payload["mrn"], "[REDACTED]")
            self.assertEqual(payload["dob"], "[REDACTED]")
            self.assertEqual(payload["diagnosis"], "[REDACTED]")
            self.assertEqual(payload["phi"], "[REDACTED]")

    def test_producer_exception_never_emits_pass_evidence(self):
        with patch(
            "security.operational_evidence.CISecurityEvidenceProducer.build_assessments",
            side_effect=RuntimeError("producer exploded"),
        ):
            with self.assertRaises(RuntimeError):
                collect_ci_evidence(
                    source_reference="auth-security-ci:broken",
                    environment="ci",
                    workflow="auth-security-ci",
                    job="sqlite-auth-regression",
                    run_id="250",
                    run_attempt="1",
                )

        self.assertEqual(SecurityEvidence.objects.count(), 0)
        self.refresh_rotation.refresh_from_db()
        self.assertEqual(self.refresh_rotation.status, SecurityControl.Status.UNKNOWN)

    @override_settings(
        AUTH_SESSION_ENFORCEMENT="ENFORCE",
        ABUSE_CONTROL_ENFORCEMENT="ENFORCE",
        JWT_REFRESH_ROTATION_ENABLED=True,
    )
    def test_configuration_command_records_pass_evidence(self):
        stdout = io.StringIO()
        call_command(
            "security_check_configuration",
            environment="production",
            source_reference="release:v1",
            stdout=stdout,
        )
        self.assertIn("Recorded configuration evidence", stdout.getvalue())
        self.session_authority.refresh_from_db()
        self.abuse.refresh_from_db()
        self.assertEqual(self.session_authority.status, SecurityControl.Status.HEALTHY)
        self.assertEqual(self.abuse.status, SecurityControl.Status.HEALTHY)

    def test_ci_command_accepts_fail_overrides(self):
        stdout = io.StringIO()
        call_command(
            "security_collect_evidence",
            environment="ci",
            source_reference="auth-security-ci:command-fail",
            workflow="auth-security-ci",
            job="sqlite-auth-regression",
            run_id="301",
            run_attempt="1",
            outcome=["GAIT.AUTH.REFRESH_ROTATION=FAIL"],
            stdout=stdout,
        )
        self.assertIn("Recorded CI evidence", stdout.getvalue())
        self.refresh_rotation.refresh_from_db()
        self.assertEqual(self.refresh_rotation.status, SecurityControl.Status.CONTROL_FAILURE)
        self.assertTrue(
            SecurityFinding.objects.filter(
                finding_key="GAIT.AUTH.REFRESH_ROTATION::ci::auth-security"
            ).exists()
        )


class OperationalEvidenceConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        sync_security_control_registry()

    def test_duplicate_concurrent_failure_ingestion_does_not_duplicate_findings(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL is required for concurrency proof.")

        template = next(
            item for item in get_ci_control_templates()
            if item.control_key == "GAIT.AUTH.REFRESH_REPLAY_PROTECTION"
        )
        context = build_ci_context(
            source_reference="auth-security-ci:concurrent",
            environment="ci",
            workflow="auth-security-ci",
            job="postgres-auth-security",
            run_id="401",
            run_attempt="1",
            outcomes={"GAIT.AUTH.REFRESH_REPLAY_PROTECTION": SecurityEvidence.Result.FAIL},
        )
        spec = template.build_spec(context, SecurityEvidence.Result.FAIL)
        barrier = threading.Barrier(2)
        results: list[str] = []

        def ingest():
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                record_assessments(spec, context=context)
                results.append("ok")
            finally:
                close_old_connections()

        threads = [threading.Thread(target=ingest), threading.Thread(target=ingest)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(results.count("ok"), 2)
        self.assertEqual(
            SecurityEvidence.objects.filter(control__control_key=template.control_key).count(),
            1,
        )
        self.assertEqual(
            SecurityFinding.objects.filter(finding_key=template.finding_key).count(),
            1,
        )
