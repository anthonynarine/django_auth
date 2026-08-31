"""A5 abuse-control tests."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from copy import deepcopy
from unittest import skipUnless

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import close_old_connections, connection
from django.test import Client, TransactionTestCase, override_settings
from django.urls import reverse

from abuse.services import record_failure as abuse_record_failure
from abuse.models import AbuseCounter
from security.models import SecurityEvent
from user.auth_token import create_temporary_2fa_token


User = get_user_model()


LOW_THRESHOLD_POLICIES = deepcopy(settings.ABUSE_CONTROL_POLICIES)
for scope in [
    "LOGIN_IP",
    "LOGIN_ACCOUNT",
    "LOGIN_IP_ACCOUNT",
    "OTP_IP",
    "OTP_SESSION",
    "OTP_ACCOUNT",
    "PASSWORD_RESET_IP",
    "PASSWORD_RESET_ACCOUNT",
]:
    LOW_THRESHOLD_POLICIES[scope]["throttle_threshold"] = 1
    LOW_THRESHOLD_POLICIES[scope]["block_threshold"] = 2
    LOW_THRESHOLD_POLICIES[scope]["block_seconds"] = 60


@override_settings(
    ABUSE_CONTROL_ENFORCEMENT="ENFORCE",
    ABUSE_CONTROL_POLICIES=LOW_THRESHOLD_POLICIES,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
class LoginAndResetAbuseControlTest(TransactionTestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.password = "correct-horse-battery"
        self.user = User.objects.create_user(email="a5-user@example.com", password=self.password)

    def test_login_throttles_after_threshold(self):
        payload = {"email": self.user.email, "password": "wrong-password"}

        response = self.client.post(reverse("login"), payload, content_type="application/json")
        self.assertEqual(response.status_code, 401)

        throttled = self.client.post(reverse("login"), payload, content_type="application/json")
        self.assertEqual(throttled.status_code, 429)
        self.assertIn("Retry-After", throttled)
        self.assertTrue(
            SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.LOGIN_THROTTLED).exists()
        )

    def test_password_reset_request_throttles_after_threshold(self):
        payload = {"email": "missing-abuse@example.com"}

        response = self.client.post(reverse("forgot_password"), payload, content_type="application/json")
        self.assertEqual(response.status_code, 200)

        throttled = self.client.post(reverse("forgot_password"), payload, content_type="application/json")
        self.assertEqual(throttled.status_code, 429)

    def test_two_factor_login_throttles_after_threshold(self):
        secret = "JBSWY3DPEHPK3PXP"
        mfa_user = User.objects.create_user(
            email="a5-mfa@example.com",
            password=self.password,
            is_2fa_enabled=True,
            tfa_secret=secret,
        )

        bad_otp = {"otp": "000000"}
        self.client.cookies["temp_token"] = create_temporary_2fa_token(mfa_user.id)
        response = self.client.post(reverse("two_factor_login"), bad_otp, content_type="application/json")
        self.assertNotEqual(response.status_code, 429)

        self.client.cookies["temp_token"] = create_temporary_2fa_token(mfa_user.id)
        throttled = self.client.post(reverse("two_factor_login"), bad_otp, content_type="application/json")
        self.assertEqual(throttled.status_code, 429)


@override_settings(ABUSE_CONTROL_ENFORCEMENT="ENFORCE")
class AbuseCounterConcurrencyTest(TransactionTestCase):
    @skipUnless(connection.vendor == "postgresql", "PostgreSQL required for abuse counter concurrency")
    def test_concurrent_failures_increment_atomically(self):
        scope = "LOGIN_ACCOUNT"
        account = "a5-concurrent@example.com"
        barrier = Barrier(10)

        def _write_failure():
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                abuse_record_failure(scope, account=account)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(lambda _: _write_failure(), range(10)))

        counter = AbuseCounter.objects.get(scope=scope)
        self.assertEqual(counter.attempt_count, 10)
        self.assertIsNotNone(counter.window_expires_at)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL required for abuse counter concurrency")
    @override_settings(
        ABUSE_CONTROL_ENFORCEMENT="ENFORCE",
        ABUSE_CONTROL_POLICIES={
            **LOW_THRESHOLD_POLICIES,
            "LOGIN_ACCOUNT": {
                "window_seconds": 60,
                "throttle_threshold": 2,
                "block_threshold": 3,
                "block_seconds": 60,
            },
        },
    )
    def test_threshold_boundary_race_is_deterministic(self):
        scope = "LOGIN_ACCOUNT"
        account = "a5-boundary@example.com"
        AbuseCounter.objects.all().delete()

        abuse_record_failure(scope, account=account)

        barrier = Barrier(2)

        def _write_failure():
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                abuse_record_failure(scope, account=account)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(lambda _: _write_failure(), range(2)))

        counter = AbuseCounter.objects.get(scope=scope)
        self.assertEqual(counter.attempt_count, 3)
        self.assertIsNotNone(counter.blocked_until)
