"""A6 step-up authentication tests."""

from __future__ import annotations

from datetime import timedelta

import pyotp
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from security.models import SecurityEvent
from user.account_security_services import is_recent_auth
from user.auth_token import create_temporary_2fa_token
from user.models import AuthSession
from user.session_services import create_session
from user.step_up import StepUpRequirement, compare_auth_strength, evaluate_step_up

User = get_user_model()


@override_settings(
    RECENT_AUTH_MAX_AGE_SECONDS=600,
    AUTH_SESSION_ENFORCEMENT="ENFORCE",
    ABUSE_CONTROL_ENFORCEMENT="ENFORCE",
)
class StepUpEvaluatorTest(TestCase):
    def setUp(self):
        cache.clear()

    def test_auth_strength_ordering_is_explicit(self):
        self.assertTrue(compare_auth_strength("mfa", "password"))
        self.assertTrue(compare_auth_strength("mfa", "mfa"))
        self.assertTrue(compare_auth_strength("password", "password"))
        self.assertFalse(compare_auth_strength("password", "mfa"))

    def test_fresh_password_session_satisfies_password_requirement(self):
        user = User.objects.create_user(email="stepup-password@example.com", password="correct-horse-battery")
        session = create_session(user, request=None, authentication_strength="password")

        evaluation = evaluate_step_up(session, StepUpRequirement(minimum_strength="password", max_auth_age_seconds=600))

        self.assertTrue(evaluation.satisfied)
        self.assertEqual(evaluation.reason_code, "STEP_UP_SATISFIED")
        self.assertEqual(evaluation.current_strength, "password")
        self.assertEqual(evaluation.required_strength, "password")
        self.assertIsNotNone(evaluation.auth_age_seconds)
        self.assertLessEqual(evaluation.auth_age_seconds, 1)

    def test_fresh_mfa_session_satisfies_password_and_mfa_requirements(self):
        user = User.objects.create_user(email="stepup-mfa@example.com", password="correct-horse-battery")
        session = create_session(user, request=None, authentication_strength="mfa")

        password_eval = evaluate_step_up(
            session,
            StepUpRequirement(minimum_strength="password", max_auth_age_seconds=600),
        )
        mfa_eval = evaluate_step_up(session, StepUpRequirement(minimum_strength="mfa", max_auth_age_seconds=600))

        self.assertTrue(password_eval.satisfied)
        self.assertTrue(mfa_eval.satisfied)

    def test_stale_password_session_fails_freshness(self):
        user = User.objects.create_user(email="stepup-stale@example.com", password="correct-horse-battery")
        session = create_session(user, request=None, authentication_strength="password")
        session.recent_auth_at = timezone.now() - timedelta(seconds=601)
        session.save(update_fields=["recent_auth_at"])

        evaluation = evaluate_step_up(session, StepUpRequirement(minimum_strength="password", max_auth_age_seconds=600))

        self.assertFalse(evaluation.satisfied)
        self.assertEqual(evaluation.reason_code, "RECENT_AUTH_REQUIRED")
        self.assertEqual(evaluation.current_strength, "password")
        self.assertEqual(evaluation.required_strength, "password")

    def test_stale_mfa_session_fails_recent_mfa_requirement(self):
        user = User.objects.create_user(email="stepup-stale-mfa@example.com", password="correct-horse-battery")
        session = create_session(user, request=None, authentication_strength="mfa")
        session.recent_auth_at = timezone.now() - timedelta(seconds=601)
        session.save(update_fields=["recent_auth_at"])

        evaluation = evaluate_step_up(session, StepUpRequirement(minimum_strength="mfa", max_auth_age_seconds=600))

        self.assertFalse(evaluation.satisfied)
        self.assertEqual(evaluation.reason_code, "RECENT_AUTH_REQUIRED")
        self.assertEqual(evaluation.current_strength, "mfa")
        self.assertEqual(evaluation.required_strength, "mfa")

    def test_is_recent_auth_still_obeys_window(self):
        user = User.objects.create_user(email="stepup-recent@example.com", password="correct-horse-battery")
        session = create_session(user, request=None, authentication_strength="password")
        session.recent_auth_at = timezone.now() - timedelta(seconds=599)
        session.save(update_fields=["recent_auth_at"])
        self.assertTrue(is_recent_auth(session, max_age_seconds=600))
        session.recent_auth_at = timezone.now() - timedelta(seconds=601)
        session.save(update_fields=["recent_auth_at"])
        self.assertFalse(is_recent_auth(session, max_age_seconds=600))


@override_settings(
    RECENT_AUTH_MAX_AGE_SECONDS=600,
    AUTH_SESSION_ENFORCEMENT="ENFORCE",
    ABUSE_CONTROL_ENFORCEMENT="ENFORCE",
)
class StepUpIntegrationTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.password = "correct-horse-battery"

    def _login(self, user):
        response = self.client.post(
            reverse("login"),
            {"email": user.email, "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def _login_mfa_user(self, user, secret):
        self.client.cookies["temp_token"] = create_temporary_2fa_token(user.id)
        response = self.client.post(
            reverse("two_factor_login"),
            {"otp": pyotp.TOTP(secret).now()},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_change_password_returns_step_up_required_for_stale_session(self):
        user = User.objects.create_user(email="stepup-change@example.com", password=self.password)
        login = self._login(user)
        session = AuthSession.objects.get(user=user)
        session.recent_auth_at = timezone.now() - timedelta(seconds=601)
        session.save(update_fields=["recent_auth_at"])

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("change_password"),
                {
                    "current_password": self.password,
                    "new_password": "brand-new-password-123",
                    "new_password_confirm": "brand-new-password-123",
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertEqual(payload["code"], "STEP_UP_REQUIRED")
        self.assertEqual(payload["reason"], "RECENT_AUTH_REQUIRED")
        self.assertEqual(payload["required_strength"], "password")
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.STEP_UP_REQUIRED,
                reason_code="RECENT_AUTH_REQUIRED",
            ).exists()
        )

    def test_validate_session_bootstraps_csrf_for_browser_step_up_requests(self):
        csrf_client = Client(enforce_csrf_checks=True)
        user = User.objects.create_user(email="stepup-csrf-browser@example.com", password=self.password)
        login = csrf_client.post(
            reverse("login"),
            {"email": user.email, "password": self.password},
            content_type="application/json",
        ).json()
        session = AuthSession.objects.get(user=user)
        session.recent_auth_at = timezone.now() - timedelta(seconds=601)
        session.save(update_fields=["recent_auth_at"])

        validate = csrf_client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
        )

        self.assertEqual(validate.status_code, 200)
        self.assertIn("X-CSRFToken", validate)
        self.assertIn("csrftoken", csrf_client.cookies)

        with self.captureOnCommitCallbacks(execute=True):
            response = csrf_client.post(
                reverse("change_password"),
                {
                    "current_password": self.password,
                    "new_password": "brand-new-password-123",
                    "new_password_confirm": "brand-new-password-123",
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
                HTTP_X_CSRFTOKEN=validate["X-CSRFToken"],
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "STEP_UP_REQUIRED")

    def test_generate_qr_requires_recent_password_step_up(self):
        user = User.objects.create_user(email="stepup-enable@example.com", password=self.password)
        login = self._login(user)
        session = AuthSession.objects.get(user=user)
        session.recent_auth_at = timezone.now() - timedelta(seconds=601)
        session.save(update_fields=["recent_auth_at"])

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.get(
                reverse("generate_qr_code"),
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertEqual(payload["code"], "STEP_UP_REQUIRED")
        self.assertEqual(payload["required_strength"], "password")
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.STEP_UP_REQUIRED,
            ).exists()
        )

    def test_reauthenticate_records_step_up_success_and_failure_for_password_user(self):
        user = User.objects.create_user(email="stepup-reauth@example.com", password=self.password)
        login = self._login(user)
        session = AuthSession.objects.get(user=user)
        before = session.recent_auth_at

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("reauthenticate"),
                {"current_password": self.password},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(response.status_code, 200)
        session.refresh_from_db()
        self.assertGreater(session.recent_auth_at, before)
        self.assertEqual(session.authentication_strength, "password")
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.STEP_UP_SUCCESS,
                reason_code="PASSWORD",
            ).exists()
        )

        before_failure = session.recent_auth_at
        with self.captureOnCommitCallbacks(execute=True):
            failure = self.client.post(
                reverse("reauthenticate"),
                {"current_password": "wrong-password"},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(failure.status_code, 400)
        session.refresh_from_db()
        self.assertEqual(session.recent_auth_at, before_failure)
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.STEP_UP_FAILURE,
                reason_code="CURRENT_PASSWORD_INVALID",
            ).exists()
        )

    def test_reauthenticate_records_step_up_success_and_failure_for_mfa_user(self):
        secret = pyotp.random_base32()
        user = User.objects.create_user(
            email="stepup-mfa-reauth@example.com",
            password=self.password,
            is_2fa_enabled=True,
            tfa_secret=secret,
        )
        login = self._login_mfa_user(user, secret)
        session = AuthSession.objects.get(user=user)
        before = session.recent_auth_at

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("reauthenticate"),
                {
                    "current_password": self.password,
                    "otp": pyotp.TOTP(secret).now(),
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(response.status_code, 200)
        session.refresh_from_db()
        self.assertGreater(session.recent_auth_at, before)
        self.assertEqual(session.authentication_strength, "mfa")
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.STEP_UP_SUCCESS,
                reason_code="PASSWORD_TOTP",
            ).exists()
        )

        before_failure = session.recent_auth_at
        with self.captureOnCommitCallbacks(execute=True):
            failure = self.client.post(
                reverse("reauthenticate"),
                {
                    "current_password": self.password,
                    "otp": "000000",
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(failure.status_code, 400)
        session.refresh_from_db()
        self.assertEqual(session.recent_auth_at, before_failure)
        self.assertEqual(session.authentication_strength, "mfa")
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.STEP_UP_FAILURE,
                reason_code="INVALID_OTP",
            ).exists()
        )

    def test_refresh_does_not_update_recent_auth_or_strength(self):
        user = User.objects.create_user(email="stepup-refresh@example.com", password=self.password)
        login = self._login(user)
        session = AuthSession.objects.get(user=user)
        before_recent = session.recent_auth_at
        before_strength = session.authentication_strength

        response = self.client.post(
            reverse("refresh"),
            {"refresh": login["refresh_token"]},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        session.refresh_from_db()
        self.assertEqual(session.recent_auth_at, before_recent)
        self.assertEqual(session.authentication_strength, before_strength)

    def test_mfa_disable_requires_recent_mfa_step_up_and_can_be_recovered(self):
        secret = pyotp.random_base32()
        user = User.objects.create_user(
            email="stepup-disable@example.com",
            password=self.password,
            is_2fa_enabled=True,
            tfa_secret=secret,
        )
        login = self._login_mfa_user(user, secret)
        session = AuthSession.objects.get(user=user)
        session.recent_auth_at = timezone.now() - timedelta(seconds=601)
        session.save(update_fields=["recent_auth_at"])

        with self.captureOnCommitCallbacks(execute=True):
            denied = self.client.patch(
                reverse("toggle_2fa"),
                {
                    "is_2fa_enabled": False,
                    "current_password": self.password,
                    "otp": pyotp.TOTP(secret).now(),
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(denied.status_code, 403)
        payload = denied.json()
        self.assertEqual(payload["code"], "STEP_UP_REQUIRED")
        self.assertEqual(payload["required_strength"], "mfa")
        self.assertTrue(user.is_2fa_enabled)

        with self.captureOnCommitCallbacks(execute=True):
            reauth = self.client.post(
                reverse("reauthenticate"),
                {
                    "current_password": self.password,
                    "otp": pyotp.TOTP(secret).now(),
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(reauth.status_code, 200)

        with self.captureOnCommitCallbacks(execute=True):
            disabled = self.client.patch(
                reverse("toggle_2fa"),
                {
                    "is_2fa_enabled": False,
                    "current_password": self.password,
                    "otp": pyotp.TOTP(secret).now(),
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
            )

        self.assertEqual(disabled.status_code, 200)
        user.refresh_from_db()
        session.refresh_from_db()
        self.assertFalse(user.is_2fa_enabled)
        self.assertEqual(session.authentication_strength, "password")
