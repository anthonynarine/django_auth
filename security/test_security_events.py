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

    def test_security_event_admin_is_read_only(self):
        event_admin = SecurityEventAdmin(SecurityEvent, admin.site)
        session_admin = AuthSessionAdmin(AuthSession, admin.site)

        self.assertFalse(event_admin.has_add_permission(None))
        self.assertFalse(event_admin.has_change_permission(None))
        self.assertFalse(event_admin.has_delete_permission(None))
        self.assertFalse(session_admin.has_add_permission(None))
        self.assertFalse(session_admin.has_change_permission(None))
        self.assertFalse(session_admin.has_delete_permission(None))


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
        self.assertEqual(event["severity_label"], "Info")
        self.assertEqual(event["reason_label"], "Password Login")
        self.assertEqual(event["session_user_email"], self.staff.email)
        self.assertIn(self.staff.email, event["session_display_name"])

        self.assertEqual(session["user_email"], self.staff.email)
        self.assertEqual(session["user_display_name"], self.staff.email)
        self.assertEqual(session["status_code"], "ACTIVE")
        self.assertEqual(session["status"], "Active")
        self.assertIn(self.staff.email, session["session_display_name"])

    def test_non_staff_is_denied(self):
        non_staff = User.objects.create_user(
            email="audit-user@example.com",
            password="correct-horse-battery",
        )
        session = create_session(non_staff, request=None)
        token = create_access_token(non_staff.id, sid=session.id)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get(reverse("security:events"))

        self.assertEqual(response.status_code, 403)
