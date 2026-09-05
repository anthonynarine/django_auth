"""B-OBS2 tests for controls, evidence, findings, and posture APIs."""

from __future__ import annotations

import threading
from datetime import timedelta

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.db import IntegrityError, close_old_connections, connection
from django.db.models.deletion import ProtectedError
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from security.admin import SecurityControlAdmin, SecurityEvidenceAdmin, SecurityFindingAdmin
from security.models import SecurityControl, SecurityEvent, SecurityEvidence, SecurityFinding
from security.selectors import derive_overall_posture_status, get_security_posture
from security.services import (
    accept_security_risk,
    acknowledge_security_finding,
    create_security_evidence,
    open_security_finding,
    refresh_control_status,
    resolve_security_finding,
    sync_security_control_registry,
)
from user.auth_token import create_access_token
from user.models import AuthSession


User = get_user_model()


def make_control(key="GAIT.TEST.CONTROL", *, status=SecurityControl.Status.UNKNOWN):
    return SecurityControl.objects.create(
        control_key=key,
        domain=SecurityControl.Domain.AUDIT,
        title="Test control",
        description="A test control.",
        control_type=SecurityControl.ControlType.LIVE,
        status=status,
        severity_if_failed=SecurityEvent.Severity.HIGH,
    )


class SecurityControlModelTest(TestCase):
    def test_control_key_is_unique(self):
        make_control()
        with self.assertRaises(IntegrityError):
            make_control()

    def test_registry_sync_creates_initial_controls_as_unknown(self):
        SecurityControl.objects.all().delete()
        result = sync_security_control_registry()
        self.assertGreaterEqual(result["created"], 1)
        self.assertTrue(SecurityControl.objects.filter(control_key="GAIT.AUTH.REFRESH_ROTATION").exists())
        self.assertFalse(SecurityControl.objects.exclude(status=SecurityControl.Status.UNKNOWN).exists())

    def test_evidence_and_finding_relationships_use_control(self):
        control = make_control()
        evidence = create_security_evidence(
            control=control,
            evidence_type=SecurityEvidence.EvidenceType.AUTOMATED_TEST,
            result=SecurityEvidence.Result.FAIL,
            title="Automated test failed",
        )
        finding, created = open_security_finding(
            finding_key="GAIT.TEST.CONTROL.FAILURE",
            control=control,
            title="Control failed",
            description="A control failed.",
            evidence=[evidence],
        )
        self.assertTrue(created)
        self.assertEqual(finding.control, control)
        self.assertEqual(list(finding.evidence.all()), [evidence])

    def test_control_delete_is_protected_by_evidence_and_findings(self):
        control = make_control()
        evidence = create_security_evidence(
            control=control,
            evidence_type=SecurityEvidence.EvidenceType.AUTOMATED_TEST,
            result=SecurityEvidence.Result.FAIL,
            title="Automated test failed",
        )
        open_security_finding(
            finding_key="GAIT.TEST.PROTECTED",
            control=control,
            title="Protected finding",
            description="A finding protects its control.",
            evidence=[evidence],
        )
        with self.assertRaises(ProtectedError):
            control.delete()

    def test_admin_behavior_is_deliberate(self):
        control_admin = SecurityControlAdmin(SecurityControl, admin.site)
        evidence_admin = SecurityEvidenceAdmin(SecurityEvidence, admin.site)
        finding_admin = SecurityFindingAdmin(SecurityFinding, admin.site)

        self.assertFalse(control_admin.has_add_permission(None))
        self.assertFalse(control_admin.has_delete_permission(None))
        self.assertFalse(evidence_admin.has_add_permission(None))
        self.assertFalse(evidence_admin.has_change_permission(None))
        self.assertFalse(evidence_admin.has_delete_permission(None))
        self.assertFalse(finding_admin.has_add_permission(None))
        self.assertFalse(finding_admin.has_delete_permission(None))


class SecurityControlEvaluationTest(TestCase):
    def setUp(self):
        self.control = make_control()

    def test_no_evidence_is_unknown(self):
        refresh_control_status(self.control)
        self.control.refresh_from_db()
        self.assertEqual(self.control.status, SecurityControl.Status.UNKNOWN)

    def test_fresh_pass_evidence_is_healthy(self):
        create_security_evidence(
            control=self.control,
            evidence_type=SecurityEvidence.EvidenceType.AUTOMATED_TEST,
            result=SecurityEvidence.Result.PASS,
            title="Passing test",
            valid_until=timezone.now() + timedelta(days=1),
        )
        self.control.refresh_from_db()
        self.assertEqual(self.control.status, SecurityControl.Status.HEALTHY)

    def test_warning_evidence_needs_attention(self):
        create_security_evidence(
            control=self.control,
            evidence_type=SecurityEvidence.EvidenceType.CONFIGURATION_CHECK,
            result=SecurityEvidence.Result.WARNING,
            title="Config warning",
        )
        self.control.refresh_from_db()
        self.assertEqual(self.control.status, SecurityControl.Status.NEEDS_ATTENTION)

    def test_fail_evidence_is_control_failure(self):
        create_security_evidence(
            control=self.control,
            evidence_type=SecurityEvidence.EvidenceType.AUTOMATED_TEST,
            result=SecurityEvidence.Result.FAIL,
            title="Failing test",
        )
        self.control.refresh_from_db()
        self.assertEqual(self.control.status, SecurityControl.Status.CONTROL_FAILURE)

    def test_expired_pass_evidence_does_not_stay_healthy(self):
        create_security_evidence(
            control=self.control,
            evidence_type=SecurityEvidence.EvidenceType.AUTOMATED_TEST,
            result=SecurityEvidence.Result.PASS,
            title="Old passing test",
            observed_at=timezone.now() - timedelta(days=10),
            valid_until=timezone.now() - timedelta(days=1),
        )
        self.control.refresh_from_db()
        self.assertEqual(self.control.status, SecurityControl.Status.NEEDS_ATTENTION)

    def test_not_applicable_remains_not_applicable(self):
        self.control.status = SecurityControl.Status.NOT_APPLICABLE
        self.control.save(update_fields=["status", "updated_at"])
        refresh_control_status(self.control)
        self.control.refresh_from_db()
        self.assertEqual(self.control.status, SecurityControl.Status.NOT_APPLICABLE)


class SecurityFindingLifecycleTest(TestCase):
    def setUp(self):
        self.control = make_control()
        self.evidence = create_security_evidence(
            control=self.control,
            evidence_type=SecurityEvidence.EvidenceType.AUTOMATED_TEST,
            result=SecurityEvidence.Result.FAIL,
            title="Failing test",
        )

    def test_open_repeat_acknowledge_resolve_and_accept_risk(self):
        finding, created = open_security_finding(
            finding_key="GAIT.TEST.REPEAT",
            control=self.control,
            title="Repeated failure",
            description="A repeated failure was detected.",
            expected_behavior="Requests should be denied.",
            observed_behavior="Request was allowed.",
            affected_system="backend",
            affected_component="security",
            evidence=[self.evidence],
            metadata={"password": "secret", "patient_name": "Jane Example", "safe": "kept"},
        )
        self.assertTrue(created)
        self.assertEqual(finding.metadata["password"], "[REDACTED]")
        self.assertEqual(finding.metadata["patient_name"], "[REDACTED]")

        first_seen = finding.first_seen_at
        last_seen = finding.last_seen_at
        repeated, created = open_security_finding(
            finding_key="GAIT.TEST.REPEAT",
            control=self.control,
            title="Repeated failure",
            description="A repeated failure was detected.",
            evidence=[self.evidence],
        )
        self.assertFalse(created)
        self.assertEqual(SecurityFinding.objects.filter(finding_key="GAIT.TEST.REPEAT").count(), 1)
        self.assertEqual(repeated.first_seen_at, first_seen)
        self.assertGreaterEqual(repeated.last_seen_at, last_seen)
        self.assertEqual(repeated.evidence.count(), 1)

        acknowledge_security_finding(repeated)
        repeated.refresh_from_db()
        self.assertEqual(repeated.status, SecurityFinding.Status.ACKNOWLEDGED)

        resolve_security_finding(repeated, resolution_summary="Fixed in backend.")
        repeated.refresh_from_db()
        self.assertEqual(repeated.status, SecurityFinding.Status.RESOLVED)
        self.assertIsNotNone(repeated.resolved_at)
        self.assertEqual(repeated.evidence.count(), 1)

        accept_security_risk(repeated, resolution_summary="Accepted for test.")
        repeated.refresh_from_db()
        self.assertEqual(repeated.status, SecurityFinding.Status.ACCEPTED_RISK)
        self.assertEqual(repeated.evidence.count(), 1)


class SecurityMetadataSanitizationTest(TestCase):
    def test_evidence_metadata_is_sanitized_on_save_and_api_output(self):
        control = make_control()
        evidence = SecurityEvidence.objects.create(
            control=control,
            evidence_type=SecurityEvidence.EvidenceType.MANUAL_VERIFICATION,
            result=SecurityEvidence.Result.INFORMATIONAL,
            title="Manual note",
            observed_at=timezone.now(),
            metadata={
                "password": "secret",
                "otp": "123456",
                "token": "jwt",
                "refresh_token": "refresh",
                "authorization": "Bearer abc",
                "mfa_secret": "totp",
                "private_key": "key",
                "safe": "kept",
            },
        )
        evidence.refresh_from_db()
        for key in ["password", "otp", "token", "refresh_token", "authorization", "mfa_secret", "private_key"]:
            self.assertEqual(evidence.metadata[key], "[REDACTED]")
        self.assertEqual(evidence.metadata["safe"], "kept")

    def test_finding_metadata_is_sanitized_on_direct_save(self):
        control = make_control()
        finding = SecurityFinding.objects.create(
            finding_key="GAIT.TEST.SANITIZE.FINDING",
            control=control,
            severity=SecurityEvent.Severity.WARNING,
            title="Sanitized finding",
            description="Finding metadata should be safe.",
            first_seen_at=timezone.now(),
            last_seen_at=timezone.now(),
            metadata={
                "patient_name": "Jane Example",
                "database_password": "secret",
                "safe": "kept",
            },
        )
        finding.refresh_from_db()
        self.assertEqual(finding.metadata["patient_name"], "[REDACTED]")
        self.assertEqual(finding.metadata["database_password"], "[REDACTED]")
        self.assertEqual(finding.metadata["safe"], "kept")


class SecurityPostureSelectorTest(TestCase):
    def test_overall_posture_is_conservative(self):
        self.assertEqual(
            derive_overall_posture_status(
                {"healthy": 10, "needs_attention": 0, "control_failure": 0, "unknown": 1, "not_applicable": 0},
                {"critical": 0, "high": 0, "warning": 0, "info": 0},
            ),
            SecurityControl.Status.UNKNOWN,
        )
        self.assertEqual(
            derive_overall_posture_status(
                {"healthy": 10, "needs_attention": 0, "control_failure": 1, "unknown": 0, "not_applicable": 0},
                {"critical": 0, "high": 0, "warning": 0, "info": 0},
            ),
            SecurityControl.Status.CONTROL_FAILURE,
        )

    def test_posture_counts_controls_and_open_findings(self):
        control = make_control(status=SecurityControl.Status.HEALTHY)
        open_security_finding(
            finding_key="GAIT.TEST.POSTURE",
            control=control,
            title="Open issue",
            description="An issue is open.",
            severity=SecurityEvent.Severity.HIGH,
        )
        posture = get_security_posture()
        self.assertEqual(posture["controls"]["healthy"], 1)
        self.assertEqual(posture["open_findings"]["high"], 1)
        self.assertEqual(posture["overall_status"], SecurityControl.Status.NEEDS_ATTENTION)


class SecurityPostureAPITest(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(email="staff-bobs2@example.com", password="pw")
        self.staff.is_staff = True
        self.staff.save(update_fields=["is_staff"])
        self.non_staff = User.objects.create_user(email="user-bobs2@example.com", password="pw")
        self.staff_session = AuthSession.objects.create(
            user=self.staff,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.non_staff_session = AuthSession.objects.create(
            user=self.non_staff,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.staff_token = create_access_token(self.staff.id, sid=self.staff_session.id)
        self.non_staff_token = create_access_token(self.non_staff.id, sid=self.non_staff_session.id)
        self.client = APIClient()
        self.control = make_control("GAIT.TEST.API")
        self.evidence = create_security_evidence(
            control=self.control,
            evidence_type=SecurityEvidence.EvidenceType.AUTOMATED_TEST,
            result=SecurityEvidence.Result.WARNING,
            title="Warning evidence",
            source_type="test",
            source_name="security",
        )
        self.finding, _ = open_security_finding(
            finding_key="GAIT.TEST.API.FINDING",
            control=self.control,
            title="API finding",
            description="A finding for API tests.",
            affected_system="backend",
            evidence=[self.evidence],
        )

    def _auth(self, token):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def test_staff_can_read_new_endpoint_families(self):
        self._auth(self.staff_token)
        endpoints = [
            reverse("security:posture"),
            reverse("security:domains"),
            reverse("security:controls"),
            reverse("security:control-detail", kwargs={"control_key": self.control.control_key}),
            reverse("security:evidence"),
            reverse("security:evidence-detail", kwargs={"pk": self.evidence.id}),
            reverse("security:findings"),
            reverse("security:finding-detail", kwargs={"pk": self.finding.id}),
        ]
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 200)

    def test_non_staff_and_anonymous_are_denied(self):
        endpoints = [
            reverse("security:posture"),
            reverse("security:domains"),
            reverse("security:controls"),
            reverse("security:evidence"),
            reverse("security:findings"),
        ]
        self._auth(self.non_staff_token)
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint, actor="non_staff"):
                self.assertEqual(self.client.get(endpoint).status_code, 403)

        self.client.credentials()
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint, actor="anonymous"):
                self.assertEqual(self.client.get(endpoint).status_code, 403)

    def test_filtering_and_pagination(self):
        self._auth(self.staff_token)
        controls = self.client.get(reverse("security:controls"), {"domain": SecurityControl.Domain.AUDIT})
        self.assertEqual(controls.status_code, 200)
        self.assertTrue(all(row["domain"] == SecurityControl.Domain.AUDIT for row in controls.json()))

        evidence = self.client.get(
            reverse("security:evidence"),
            {
                "control": self.control.control_key,
                "evidence_type": SecurityEvidence.EvidenceType.AUTOMATED_TEST,
                "result": SecurityEvidence.Result.WARNING,
                "page_size": 1,
            },
        )
        self.assertEqual(evidence.status_code, 200)
        self.assertIn("results", evidence.json())
        self.assertEqual(evidence.json()["results"][0]["id"], str(self.evidence.id))

        findings = self.client.get(
            reverse("security:findings"),
            {
                "status": SecurityFinding.Status.OPEN,
                "severity": SecurityEvent.Severity.HIGH,
                "domain": SecurityControl.Domain.AUDIT,
                "control": self.control.control_key,
                "affected_system": "backend",
                "page_size": 1,
            },
        )
        self.assertEqual(findings.status_code, 200)
        self.assertEqual(findings.json()["results"][0]["id"], str(self.finding.id))

    def test_public_endpoints_are_read_only(self):
        self._auth(self.staff_token)
        response = self.client.post(reverse("security:controls"), {"control_key": "NOPE"}, format="json")
        self.assertEqual(response.status_code, 405)


class SecurityFindingRaceSafetyTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.control = make_control("GAIT.TEST.RACE")

    def test_duplicate_finding_creation_has_one_logical_finding(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL row locking is required for this race-safety test.")

        errors = []

        def worker():
            try:
                close_old_connections()
                open_security_finding(
                    finding_key="GAIT.TEST.RACE.DEDUPE",
                    control=self.control.control_key,
                    title="Race finding",
                    description="Concurrent detection of one condition.",
                )
            except Exception as exc:
                errors.append(exc)
            finally:
                close_old_connections()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(SecurityFinding.objects.filter(finding_key="GAIT.TEST.RACE.DEDUPE").count(), 1)
