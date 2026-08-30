"""
Tests for the security hardening patches:
- Rate limiting on login, OTP verification, and password-reset requests.
- Password reset tokens expiring via PASSWORD_RESET_TIMEOUT.
- Sensitive values (passwords, tokens, OTPs) no longer appearing in logs.
- DisableCSRFMiddleware using an explicit allowlist instead of exempting
  all of /api/.
"""
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.cache import cache
from django.test import TestCase, Client, RequestFactory, override_settings
from django.urls import reverse
from django.utils import timezone

from authentication.custom_middleware.disable_csrf import DisableCSRFMiddleware
from user.auth_token import create_refresh_token
from user.models import Reset, UserToken

User = get_user_model()


class LoginThrottleTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(email="throttle@example.com", password="correct-horse-battery")

    def test_login_is_throttled_after_five_attempts_per_minute(self):
        bad_credentials = {"email": "throttle@example.com", "password": "wrong-password"}

        for _ in range(5):
            response = self.client.post(reverse("login"), bad_credentials, content_type="application/json")
            self.assertNotEqual(response.status_code, 429)

        sixth_response = self.client.post(reverse("login"), bad_credentials, content_type="application/json")
        self.assertEqual(sixth_response.status_code, 429)


class OtpThrottleTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()

    def test_two_factor_login_is_throttled_after_five_attempts_per_minute(self):
        self.client.cookies["temp_token"] = "not-a-real-token"
        bad_otp = {"otp": "000000"}

        for _ in range(5):
            response = self.client.post(reverse("two_factor_login"), bad_otp, content_type="application/json")
            self.assertNotEqual(response.status_code, 429)

        sixth_response = self.client.post(reverse("two_factor_login"), bad_otp, content_type="application/json")
        self.assertEqual(sixth_response.status_code, 429)


class PasswordResetExpiryTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email="resetme@example.com", password="original-password")

    def _create_reset(self):
        token = PasswordResetTokenGenerator().make_token(self.user)
        Reset.objects.create(email=self.user.email, token=token)
        return token

    def test_valid_unexpired_token_resets_password(self):
        token = self._create_reset()
        payload = {
            "password": "brand-new-password-123",
            "password_confirm": "brand-new-password-123",
            "token": token,
        }
        response = self.client.post(reverse("reset_password"), payload, content_type="application/json")
        self.assertEqual(response.status_code, 202)

    @override_settings(PASSWORD_RESET_TIMEOUT=1)
    def test_expired_token_is_rejected(self):
        import time

        token = self._create_reset()
        time.sleep(2)  # exceed the 1-second timeout enforced above

        payload = {
            "password": "brand-new-password-123",
            "password_confirm": "brand-new-password-123",
            "token": token,
        }
        response = self.client.post(reverse("reset_password"), payload, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        # The user's original password must be untouched.
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("original-password"))


class LogScrubbingTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.password = "UnmistakableSecretPassphrase987"
        self.user = User.objects.create_user(email="logtest@example.com", password=self.password)

    def test_login_does_not_log_plaintext_password(self):
        with self.assertLogs("user.views", level="DEBUG") as cm:
            self.client.post(
                reverse("login"),
                {"email": "logtest@example.com", "password": self.password},
                content_type="application/json",
            )
        combined_output = "\n".join(cm.output)
        self.assertNotIn(self.password, combined_output)

    def test_register_does_not_log_plaintext_password(self):
        registration_data = {
            "email": "newlogtest@example.com",
            "first_name": "Log",
            "last_name": "Test",
            "password": self.password,
            "password_confirm": self.password,
        }
        with self.assertLogs("user.views", level="DEBUG") as cm:
            self.client.post(reverse("register"), registration_data, content_type="application/json")
        combined_output = "\n".join(cm.output)
        self.assertNotIn(self.password, combined_output)


class DisableCSRFMiddlewareAllowlistTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = DisableCSRFMiddleware(get_response=lambda request: None)

    def test_known_public_endpoint_is_exempt(self):
        request = self.factory.post("/api/login/")
        self.middleware.process_request(request)
        self.assertTrue(getattr(request, "_dont_enforce_csrf_checks", False))

    def test_unlisted_future_endpoint_is_not_exempt(self):
        request = self.factory.post("/api/some-new-endpoint-not-yet-added/")
        self.middleware.process_request(request)
        self.assertFalse(getattr(request, "_dont_enforce_csrf_checks", False))


class RefreshTokenTransportTest(TestCase):
    """
    RefreshAPIView must accept the refresh token from the Authorization
    header (primary) or the request body (fallback, for clients like
    Lumen's dev-mode authApi that send {"refresh": "..."}).
    """

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email="refreshme@example.com", password="whatever-password")
        self.refresh_token = create_refresh_token(self.user.id)
        UserToken.objects.create(
            user=self.user,
            token=self.refresh_token,
            expired_at=timezone.now() + timedelta(days=7),
        )

    def test_refresh_via_authorization_header(self):
        response = self.client.post(
            reverse("refresh"),
            {},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.refresh_token}",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())

    def test_refresh_via_body_key_refresh(self):
        response = self.client.post(
            reverse("refresh"),
            {"refresh": self.refresh_token},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())

    def test_refresh_via_body_key_refresh_token(self):
        response = self.client.post(
            reverse("refresh"),
            {"refresh_token": self.refresh_token},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())

    def test_stale_access_token_in_header_is_rejected(self):
        """
        Sending an access token (wrong secret) where a refresh token is
        expected must fail -- this is exactly the bug found in Lumen's
        frontend: a stale access token left on the Authorization header
        instead of the refresh token.
        """
        from user.auth_token import create_access_token

        stale_access_token = create_access_token(self.user.id)
        response = self.client.post(
            reverse("refresh"),
            {},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {stale_access_token}",
        )
        # RefreshAPIView has no authentication_classes, so DRF downgrades
        # AuthenticationFailed to 403 (no WWW-Authenticate header to justify
        # 401) -- pre-existing behavior, unrelated to this fix.
        self.assertEqual(response.status_code, 403)


class RabbitMqPublishFallbackTest(TestCase):
    """RabbitMQ publication should not break auth flows when unconfigured."""

    @patch("user.rabbitmq_producer.pika.BlockingConnection")
    @patch("user.rabbitmq_producer.config", return_value="")
    def test_missing_cloudamqp_url_skips_publish(self, mock_config, mock_connection):
        from user.rabbitmq_producer import send_user_registered_message

        send_user_registered_message(
            {
                "id": 1,
                "email": "fallback@example.com",
                "first_name": "Fallback",
                "last_name": "User",
            }
        )

        mock_config.assert_called_once_with("CLOUDAMQP_URL", default="")
        mock_connection.assert_not_called()
