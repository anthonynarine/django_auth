"""A3 regression tests for durable security events."""

from __future__ import annotations

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from security.admin import AuthSessionAdmin, SecurityEventAdmin
from security.models import SecurityEvent
from security.presentation import EVENT_TEMPLATES, EventCategory, describe_security_event
from security.services import record_security_event
from user.auth_token import create_access_token
from user.models import AuthSession
from user.session_services import create_session

User = get_user_model()


class SecurityEventServiceTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_record_security_event_sanitizes_sensitive_metadata(self):
        request = self.factory.post(
            "/api/security/events/",
            HTTP_USER_AGENT="AuditTest/1.0",
            REMOTE_ADDR="203.0.113.10",
        )

        with self.captureOnCommitCallbacks(execute=True):
            record_security_event(
                SecurityEvent.EventType.LOGIN_FAILURE,
                request=request,
                reason_code="INVALID_PASSWORD",
                metadata={
                    "password": "super-secret",
                    "otp": "123456",
                    "nested": {"refresh_token": "also-secret"},
                    "safe_value": "kept",
                },
            )

        event = SecurityEvent.objects.get()
        self.assertEqual(event.request_method, "POST")
        self.assertEqual(event.request_path, "/api/security/events/")
        self.assertEqual(event.ip_address, "203.0.113.10")
        self.assertEqual(event.user_agent, "AuditTest/1.0")
        self.assertEqual(event.metadata["password"], "[REDACTED]")
        self.assertEqual(event.metadata["otp"], "[REDACTED]")
        self.assertEqual(event.metadata["nested"]["refresh_token"], "[REDACTED]")
        self.assertEqual(event.metadata["safe_value"], "kept")

    def test_step_up_events_use_expected_defaults(self):
        request = self.factory.post("/api/reauthenticate/")

        with self.captureOnCommitCallbacks(execute=True):
            record_security_event(
                SecurityEvent.EventType.STEP_UP_REQUIRED,
                request=request,
                reason_code="RECENT_AUTH_REQUIRED",
            )
            record_security_event(
                SecurityEvent.EventType.STEP_UP_SUCCESS,
                request=request,
                reason_code="PASSWORD",
            )
            record_security_event(
                SecurityEvent.EventType.STEP_UP_FAILURE,
                request=request,
                reason_code="INVALID_OTP",
            )

        self.assertEqual(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.STEP_UP_REQUIRED).get().outcome,
            SecurityEvent.Outcome.DENIED,
        )
        self.assertEqual(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.STEP_UP_REQUIRED).get().severity,
            SecurityEvent.Severity.WARNING,
        )
        self.assertEqual(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.STEP_UP_SUCCESS).get().outcome,
            SecurityEvent.Outcome.SUCCESS,
        )
        self.assertEqual(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.STEP_UP_SUCCESS).get().severity,
            SecurityEvent.Severity.INFO,
        )
        self.assertEqual(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.STEP_UP_FAILURE).get().outcome,
            SecurityEvent.Outcome.FAILURE,
        )
        self.assertEqual(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.STEP_UP_FAILURE).get().severity,
            SecurityEvent.Severity.WARNING,
        )

    def test_security_event_admin_is_read_only(self):
        event_admin = SecurityEventAdmin(SecurityEvent, admin.site)
        session_admin = AuthSessionAdmin(AuthSession, admin.site)

        self.assertFalse(event_admin.has_add_permission(None))
        self.assertFalse(event_admin.has_change_permission(None))
        self.assertFalse(event_admin.has_delete_permission(None))
        self.assertFalse(session_admin.has_add_permission(None))
        self.assertFalse(session_admin.has_change_permission(None))
        self.assertFalse(session_admin.has_delete_permission(None))


class SecurityEventPresentationTest(TestCase):
    def _event(self, event_type, *, severity=SecurityEvent.Severity.INFO, reason_code=""):
        return SecurityEvent(
            event_type=event_type,
            outcome=SecurityEvent.Outcome.SUCCESS,
            severity=severity,
            reason_code=reason_code,
            metadata={},
        )

    def test_representative_event_mappings_are_human_readable(self):
        cases = [
            (
                SecurityEvent.EventType.LOGIN_SUCCESS,
                SecurityEvent.Severity.INFO,
                "Successful sign-in",
                EventCategory.AUTHENTICATION,
                "Authentication",
                "Normal activity",
                "Allowed",
                "No action required.",
            ),
            (
                SecurityEvent.EventType.LOGIN_FAILURE,
                SecurityEvent.Severity.WARNING,
                "Sign-in attempt failed",
                EventCategory.AUTHENTICATION,
                "Authentication",
                "Needs attention",
                "Authentication failed",
                "No action required unless repeated or unexpected attempts continue.",
            ),
            (
                SecurityEvent.EventType.SESSION_REVOKED,
                SecurityEvent.Severity.INFO,
                "Session revoked",
                EventCategory.SESSION_SECURITY,
                "Session security",
                "Normal activity",
                "Session revoked",
                "No action required if this revocation was expected.",
            ),
            (
                SecurityEvent.EventType.REFRESH_REPLAY_DETECTED,
                SecurityEvent.Severity.HIGH,
                "Previously used session token detected",
                EventCategory.SESSION_SECURITY,
                "Session security",
                "Security concern",
                "Request blocked and affected authentication authority revoked",
                "Review the affected account if this activity was unexpected.",
            ),
            (
                SecurityEvent.EventType.STEP_UP_REQUIRED,
                SecurityEvent.Severity.WARNING,
                "Additional identity verification required",
                EventCategory.STEP_UP,
                "Step-up verification",
                "Needs attention",
                "Additional authentication required",
                "No action required if the user intentionally initiated the sensitive operation.",
            ),
            (
                SecurityEvent.EventType.STEP_UP_SUCCESS,
                SecurityEvent.Severity.INFO,
                "Additional identity verification completed",
                EventCategory.STEP_UP,
                "Step-up verification",
                "Normal activity",
                "Allowed",
                "No action required.",
            ),
            (
                SecurityEvent.EventType.STEP_UP_FAILURE,
                SecurityEvent.Severity.WARNING,
                "Additional identity verification failed",
                EventCategory.STEP_UP,
                "Step-up verification",
                "Needs attention",
                "Authentication failed",
                "No action required unless repeated or unexpected attempts continue.",
            ),
            (
                SecurityEvent.EventType.REAUTH_THROTTLED,
                SecurityEvent.Severity.WARNING,
                "Too many identity-verification attempts were throttled",
                EventCategory.ABUSE_CONTROL,
                "Abuse control",
                "Needs attention",
                "Temporarily throttled",
                "No action required unless the activity was unexpected.",
            ),
            (
                SecurityEvent.EventType.MFA_ENABLED,
                SecurityEvent.Severity.INFO,
                "Multi-factor authentication enabled",
                EventCategory.MFA,
                "Multi-factor authentication",
                "Normal activity",
                "Allowed",
                "No action required if this change was expected.",
            ),
            (
                SecurityEvent.EventType.PASSWORD_RESET_REQUESTED,
                SecurityEvent.Severity.INFO,
                "Password reset requested",
                EventCategory.ACCOUNT_SECURITY,
                "Account security",
                "Normal activity",
                "Request accepted",
                "No action required unless repeated or unexpected requests continue.",
            ),
        ]

        for event_type, severity, title, category, category_label, severity_label, system_response, action in cases:
            with self.subTest(event_type=event_type):
                presentation = describe_security_event(self._event(event_type, severity=severity))
                self.assertEqual(presentation.title, title)
                self.assertEqual(presentation.category, category)
                self.assertEqual(presentation.category_label, category_label)
                self.assertEqual(presentation.severity_label, severity_label)
                self.assertTrue(presentation.description)
                self.assertEqual(presentation.system_response, system_response)
                self.assertEqual(presentation.recommended_action, action)

    def test_reason_code_specializes_step_up_required(self):
        generic = describe_security_event(
            self._event(SecurityEvent.EventType.STEP_UP_REQUIRED, reason_code="")
        )
        specialized = describe_security_event(
            self._event(SecurityEvent.EventType.STEP_UP_REQUIRED, reason_code="RECENT_AUTH_REQUIRED")
        )

        self.assertNotEqual(generic.description, specialized.description)
        self.assertIn("too old", specialized.description)

    def test_unknown_event_falls_back_safely(self):
        event = self._event("NEW_FUTURE_EVENT", severity=SecurityEvent.Severity.CRITICAL)

        presentation = describe_security_event(event)

        self.assertEqual(event.event_type, "NEW_FUTURE_EVENT")
        self.assertEqual(presentation.title, "Security activity recorded")
        self.assertEqual(presentation.description, "Gait recorded a security-related event.")
        self.assertEqual(presentation.category, EventCategory.SYSTEM_SECURITY)
        self.assertEqual(presentation.severity_label, "Immediate attention")

    def test_all_current_event_types_have_explicit_mappings(self):
        missing = [
            event_type
            for event_type, _label in SecurityEvent.EventType.choices
            if event_type not in EVENT_TEMPLATES
        ]

        self.assertEqual(missing, [])


class SecurityEventFlowTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.password = "correct-horse-battery"
        self.user = User.objects.create_user(
            email="audit@example.com",
            password=self.password,
        )

    def _login(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("login"),
                {"email": self.user.email, "password": self.password},
                content_type="application/json",
            )
        return response

    def _make_refresh_session(self):
        login_response = self._login()
        return login_response.json()["access_token"], login_response.json()["refresh_token"]

    def test_login_records_success_and_session_creation(self):
        self.assertEqual(SecurityEvent.objects.count(), 0)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("login"),
                {"email": self.user.email, "password": self.password},
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.SESSION_CREATED).exists()
        )
        self.assertTrue(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.LOGIN_SUCCESS).exists()
        )

    def test_login_failure_records_failure_event(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("login"),
                {"email": self.user.email, "password": "wrong-password"},
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 401)
        self.assertTrue(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.LOGIN_FAILURE).exists()
        )

    def test_refresh_success_records_rotation_event(self):
        access_token, refresh_token = self._make_refresh_session()
        self.assertTrue(access_token)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("refresh"),
                {"refresh": refresh_token},
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.TOKEN_REFRESHED).exists()
        )

    def test_refresh_replay_records_replay_and_session_revocation(self):
        _, refresh_token = self._make_refresh_session()
        self.client.post(
            reverse("refresh"),
            {"refresh": refresh_token},
            content_type="application/json",
        )

        with self.captureOnCommitCallbacks(execute=True):
            replay_response = self.client.post(
                reverse("refresh"),
                {"refresh": refresh_token},
                content_type="application/json",
            )

        self.assertEqual(replay_response.status_code, 403)
        self.assertTrue(
            SecurityEvent.objects.filter(
                event_type=SecurityEvent.EventType.REFRESH_REPLAY_DETECTED
            ).exists()
        )
        self.assertTrue(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.SESSION_REVOKED).exists()
        )

    def test_logout_all_records_summary_event(self):
        first_login = self._login()
        second_login = self._login()
        first_access = first_login.json()["access_token"]

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("logout_all"),
                HTTP_AUTHORIZATION=f"Bearer {first_access}",
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.LOGOUT_ALL).exists()
        )
        self.assertTrue(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.SESSION_REVOKED).exists()
        )
        self.assertFalse(
            AuthSession.objects.filter(user=self.user, revoked_at__isnull=True).exists()
        )

    def test_password_reset_records_requested_and_completed_events(self):
        with self.captureOnCommitCallbacks(execute=True):
            request_response = self.client.post(
                reverse("forgot_password"),
                {"email": self.user.email},
                content_type="application/json",
            )

        self.assertEqual(request_response.status_code, 200)
        self.assertTrue(
            SecurityEvent.objects.filter(
                event_type=SecurityEvent.EventType.PASSWORD_RESET_REQUESTED
            ).exists()
        )

        from user.models import Reset

        reset_token = Reset.objects.filter(email=self.user.email).order_by("-id").values_list("token", flat=True).first()

        with self.captureOnCommitCallbacks(execute=True):
            reset_response = self.client.post(
                reverse("reset_password"),
                {
                    "password": "brand-new-password-123",
                    "password_confirm": "brand-new-password-123",
                    "token": reset_token,
                },
                content_type="application/json",
            )

        self.assertEqual(reset_response.status_code, 202)
        self.assertTrue(
            SecurityEvent.objects.filter(
                event_type=SecurityEvent.EventType.PASSWORD_RESET_COMPLETED
            ).exists()
        )

    def test_inactive_user_denial_records_event(self):
        login_response = self._login()
        access_token = login_response.json()["access_token"]

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.get(
                reverse("fetch_user"),
                HTTP_AUTHORIZATION=f"Bearer {access_token}",
            )

        self.assertEqual(response.status_code, 401)
        self.assertTrue(
            SecurityEvent.objects.filter(
                event_type=SecurityEvent.EventType.INACTIVE_USER_DENIED
            ).exists()
        )


class SecurityReadAccessTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.staff = User.objects.create_user(
            email="audit-staff@example.com",
            password="correct-horse-battery",
            is_staff=True,
        )
        self.session = create_session(self.staff, request=None)
        self.access_token = create_access_token(self.staff.id, sid=self.session.id)

        with self.captureOnCommitCallbacks(execute=True):
            record_security_event(
                SecurityEvent.EventType.LOGIN_SUCCESS,
                user=self.staff,
                auth_session=self.session,
                reason_code="PASSWORD_LOGIN",
            )

    def test_staff_can_read_events_summary_and_sessions(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")

        events_response = self.client.get(reverse("security:events"))
        summary_response = self.client.get(reverse("security:summary"))
        sessions_response = self.client.get(reverse("security:sessions"))

        self.assertEqual(events_response.status_code, 200)
        self.assertEqual(summary_response.status_code, 200)
        self.assertEqual(sessions_response.status_code, 200)
        self.assertIn("results", events_response.json())
        self.assertIn("successful_logins", summary_response.json())
        self.assertIn("results", sessions_response.json())

        event = events_response.json()["results"][0]
        session = sessions_response.json()["results"][0]

        self.assertEqual(event["user_email"], self.staff.email)
        self.assertEqual(event["event_label"], "Login success")
        self.assertEqual(event["outcome_label"], "Success")
        self.assertEqual(event["severity_label"], "Normal activity")
        self.assertEqual(event["title"], "Successful sign-in")
        self.assertEqual(event["category"], "AUTHENTICATION")
        self.assertEqual(event["category_label"], "Authentication")
        self.assertEqual(event["system_response"], "Allowed")
        self.assertEqual(event["recommended_action"], "No action required.")
        self.assertEqual(event["reason_label"], "Password Login")
        self.assertEqual(event["session_user_email"], self.staff.email)
        self.assertIn(self.staff.email, event["session_display_name"])

        self.assertEqual(session["user_email"], self.staff.email)
        self.assertEqual(session["user_display_name"], self.staff.email)
        self.assertEqual(session["status_code"], "ACTIVE")
        self.assertEqual(session["status"], "Active")
        self.assertEqual(
            session["status_description"],
            "This session is currently active and may access protected resources according to normal authorization policy.",
        )
        self.assertIn(self.staff.email, session["session_display_name"])

        event_detail_response = self.client.get(
            reverse("security:event-detail", kwargs={"pk": event["id"]})
        )
        session_detail_response = self.client.get(
            reverse("security:session-detail", kwargs={"pk": session["id"]})
        )
        self.assertEqual(event_detail_response.status_code, 200)
        self.assertEqual(session_detail_response.status_code, 200)
        self.assertEqual(event_detail_response.json()["title"], "Successful sign-in")
        self.assertEqual(session_detail_response.json()["status"], "Active")
        self.assertIn("category_labels", summary_response.json())
        self.assertIn("severity_labels", summary_response.json())

    def test_event_api_preserves_core_fields_and_redacts_sensitive_metadata(self):
        with self.captureOnCommitCallbacks(execute=True):
            record_security_event(
                SecurityEvent.EventType.REFRESH_REPLAY_DETECTED,
                user=self.staff,
                auth_session=self.session,
                outcome=SecurityEvent.Outcome.REVOKED,
                severity=SecurityEvent.Severity.HIGH,
                reason_code="REFRESH_REPLAY",
                metadata={
                    "password": "plain-password",
                    "otp": "123456",
                    "token": "access-token",
                    "refresh_token": "refresh-token",
                    "authorization": "Bearer token",
                    "mfa_secret": "mfa-secret-value",
                    "safe_detail": "kept",
                },
            )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")

        event = SecurityEvent.objects.get(event_type=SecurityEvent.EventType.REFRESH_REPLAY_DETECTED)
        response = self.client.get(reverse("security:event-detail", kwargs={"pk": event.id}))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        for field in ["id", "event_type", "outcome", "severity", "reason_code", "metadata"]:
            self.assertIn(field, payload)
        self.assertEqual(payload["event_type"], SecurityEvent.EventType.REFRESH_REPLAY_DETECTED)
        self.assertEqual(payload["severity"], SecurityEvent.Severity.HIGH)
        self.assertEqual(payload["severity_label"], "Security concern")
        self.assertEqual(payload["metadata"]["safe_detail"], "kept")
        self.assertEqual(payload["metadata"]["password"], "[REDACTED]")
        self.assertEqual(payload["metadata"]["otp"], "[REDACTED]")
        self.assertEqual(payload["metadata"]["token"], "[REDACTED]")
        self.assertEqual(payload["metadata"]["refresh_token"], "[REDACTED]")
        self.assertEqual(payload["metadata"]["authorization"], "[REDACTED]")
        self.assertEqual(payload["metadata"]["mfa_secret"], "[REDACTED]")
        rendered = str(payload)
        self.assertNotIn("plain-password", rendered)
        self.assertNotIn("123456", rendered)
        self.assertNotIn("access-token", rendered)
        self.assertNotIn("refresh-token", rendered)
        self.assertNotIn("Bearer token", rendered)
        self.assertNotIn("mfa-secret-value", rendered)

    def test_event_api_returns_safe_fallback_for_unmapped_event_type(self):
        event = SecurityEvent.objects.create(
            event_type="NEW_FUTURE_EVENT",
            outcome=SecurityEvent.Outcome.SUCCESS,
            severity=SecurityEvent.Severity.WARNING,
            user=self.staff,
            auth_session=self.session,
            metadata={},
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")

        response = self.client.get(reverse("security:event-detail", kwargs={"pk": event.id}))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["event_type"], "NEW_FUTURE_EVENT")
        self.assertEqual(payload["title"], "Security activity recorded")
        self.assertEqual(payload["description"], "Gait recorded a security-related event.")
        self.assertEqual(payload["category"], "SYSTEM_SECURITY")
        self.assertEqual(payload["severity_label"], "Needs attention")

    def test_non_staff_is_denied_from_observatory_endpoints(self):
        non_staff = User.objects.create_user(
            email="audit-user@example.com",
            password="correct-horse-battery",
        )
        session = create_session(non_staff, request=None)
        token = create_access_token(non_staff.id, sid=session.id)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        endpoints = [
            reverse("security:events"),
            reverse("security:event-detail", kwargs={"pk": SecurityEvent.objects.first().id}),
            reverse("security:summary"),
            reverse("security:sessions"),
            reverse("security:session-detail", kwargs={"pk": self.session.id}),
        ]

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 403)

    def test_anonymous_user_is_denied_from_observatory_endpoints(self):
        self.client.credentials()

        endpoints = [
            reverse("security:events"),
            reverse("security:event-detail", kwargs={"pk": SecurityEvent.objects.first().id}),
            reverse("security:summary"),
            reverse("security:sessions"),
            reverse("security:session-detail", kwargs={"pk": self.session.id}),
        ]

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertIn(response.status_code, [401, 403])
