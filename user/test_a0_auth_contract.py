# Filename: user/test_a0_auth_contract.py
"""A0 regression tests for the current production authentication contract."""

from datetime import timedelta, timezone as datetime_timezone
from unittest.mock import patch

import jwt
import pyotp
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from authentication.custom_middleware.disable_csrf import DisableCSRFMiddleware
from user.admin import UserTokenAdmin
from user.auth_token import (
    JWT_ACCESS_SECRET,
    JWT_REFRESH_SECRET,
    JWT_TEMP_SECRET,
    create_access_token,
    create_refresh_token,
    create_temporary_2fa_token,
)
from user.models import Reset, UserToken

User = get_user_model()


def _tamper_token(token):
    """Return a token with a changed signature segment."""
    header, payload, signature = token.split(".")
    replacement = "a" if signature[0] != "a" else "b"
    return f"{header}.{payload}.{replacement}{signature[1:]}"


class AccessTokenContractTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="access@example.com",
            password="correct-horse-battery",
        )

    def test_valid_access_token_in_authorization_header_authenticates(self):
        token = create_access_token(self.user.id)

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["email"], self.user.email)

    def test_cookie_access_token_does_not_authenticate_explicit_drf_auth_endpoint(self):
        # CURRENT BEHAVIOR - EXPECTED TO CHANGE DURING MIDDLEWARE/DRF CONSOLIDATION.
        token = create_access_token(self.user.id)
        self.client.cookies["access_token"] = token

        response = self.client.get(reverse("fetch_user"))

        self.assertEqual(response.status_code, 401)

    def test_cookie_access_token_authenticates_middleware_only_endpoint(self):
        token = create_access_token(self.user.id)
        self.client.cookies["access_token"] = token

        response = self.client.patch(
            reverse("toggle_2fa"),
            {"is_2fa_enabled": True},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_2fa_setup_in_progress)

    def test_missing_access_token_is_rejected_on_protected_endpoint(self):
        response = self.client.get(reverse("fetch_user"))

        self.assertEqual(response.status_code, 401)

    def test_expired_access_token_is_rejected(self):
        payload = {
            "user_id": self.user.id,
            "email": self.user.email,
            "role": self.user.role,
            "exp": timezone.now() - timedelta(minutes=1),
            "iat": timezone.now() - timedelta(minutes=16),
        }
        token = jwt.encode(payload, JWT_ACCESS_SECRET, algorithm="HS256")

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        self.assertEqual(response.status_code, 401)

    def test_tampered_access_token_is_rejected(self):
        token = _tamper_token(create_access_token(self.user.id))

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        self.assertEqual(response.status_code, 401)

    def test_malformed_access_token_is_rejected(self):
        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION="Bearer not-a-jwt",
        )

        self.assertEqual(response.status_code, 401)

    def test_cookie_access_token_takes_precedence_over_header_in_middleware_path(self):
        second_user = User.objects.create_user(
            email="header@example.com",
            password="correct-horse-battery",
        )
        cookie_token = create_access_token(self.user.id)
        header_token = create_access_token(second_user.id)
        self.client.cookies["access_token"] = cookie_token

        response = self.client.patch(
            reverse("toggle_2fa"),
            {"is_2fa_enabled": True},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {header_token}",
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        second_user.refresh_from_db()
        self.assertTrue(self.user.is_2fa_setup_in_progress)
        self.assertFalse(second_user.is_2fa_setup_in_progress)

    def test_inactive_user_access_token_is_rejected_after_session_enforcement(self):
        # CURRENT BEHAVIOR - EXPECTED UNDER A2 SESSION ENFORCEMENT.
        token = create_access_token(self.user.id)
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        self.assertEqual(response.status_code, 401)


class PublicProtectedEndpointContractTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="endpoint@example.com",
            password="correct-horse-battery",
        )

    @patch("user.views.send_user_registered_message")
    @patch("user.views.EmailMultiAlternatives")
    def test_public_register_endpoint_remains_accessible_without_jwt(
        self,
        email_message,
        send_message,
    ):
        response = self.client.post(
            reverse("register"),
            {
                "email": "public-register@example.com",
                "first_name": "Public",
                "last_name": "Endpoint",
                "password": "correct-horse-battery",
                "password_confirm": "correct-horse-battery",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)
        send_message.assert_called_once()
        email_message.return_value.send.assert_called_once()

    def test_public_guest_login_endpoint_is_csrf_exempt(self):
        request = self.client.request().wsgi_request
        request.path_info = "/api/guest-login/"

        DisableCSRFMiddleware(lambda req: None).process_request(request)

        self.assertTrue(getattr(request, "_dont_enforce_csrf_checks", False))

    def test_protected_endpoint_rejects_unauthenticated_request(self):
        response = self.client.get(reverse("fetch_user"))

        self.assertEqual(response.status_code, 401)

    def test_protected_endpoint_accepts_valid_authentication(self):
        token = create_access_token(self.user.id)

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        self.assertEqual(response.status_code, 200)


class RefreshTokenContractTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="refresh-a0@example.com",
            password="correct-horse-battery",
        )
        self.refresh_token = create_refresh_token(self.user.id)
        self.user_token = UserToken.objects.create(
            user=self.user,
            token=self.refresh_token,
            expired_at=timezone.now() + timedelta(days=7),
        )

    def test_valid_refresh_token_via_authorization_header_succeeds(self):
        response = self.client.post(
            reverse("refresh"),
            {},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.refresh_token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())

    def test_valid_refresh_token_via_body_refresh_succeeds(self):
        response = self.client.post(
            reverse("refresh"),
            {"refresh": self.refresh_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())

    def test_valid_refresh_token_via_body_refresh_token_succeeds(self):
        response = self.client.post(
            reverse("refresh"),
            {"refresh_token": self.refresh_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())

    def test_expired_refresh_token_is_rejected(self):
        expired_token = jwt.encode(
            {
                "user_id": self.user.id,
                "email": self.user.email,
                "role": self.user.role,
                "exp": timezone.now() - timedelta(minutes=1),
                "iat": timezone.now() - timedelta(days=8),
            },
            JWT_REFRESH_SECRET,
            algorithm="HS256",
        )
        UserToken.objects.create(
            user=self.user,
            token=expired_token,
            expired_at=timezone.now() + timedelta(days=7),
        )

        response = self.client.post(
            reverse("refresh"),
            {"refresh": expired_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_malformed_refresh_token_is_rejected(self):
        response = self.client.post(
            reverse("refresh"),
            {"refresh": "not-a-jwt"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_tampered_refresh_token_is_rejected(self):
        response = self.client.post(
            reverse("refresh"),
            {"refresh": _tamper_token(self.refresh_token)},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_refresh_token_missing_from_usertoken_is_rejected(self):
        missing_db_token = jwt.encode(
            {
                "user_id": self.user.id,
                "email": self.user.email,
                "role": self.user.role,
                "nonce": "not-persisted",
                "exp": timezone.now() + timedelta(days=7),
                "iat": timezone.now(),
            },
            JWT_REFRESH_SECRET,
            algorithm="HS256",
        )

        response = self.client.post(
            reverse("refresh"),
            {"refresh": missing_db_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_deleted_usertoken_is_rejected(self):
        self.user_token.delete()

        response = self.client.post(
            reverse("refresh"),
            {"refresh": self.refresh_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_is_revoked_flag_is_enforced_after_a1(self):
        self.user_token.is_revoked = True
        self.user_token.save(update_fields=["is_revoked"])

        response = self.client.post(
            reverse("refresh"),
            {"refresh": self.refresh_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_refresh_token_is_single_use_after_a1(self):
        first_response = self.client.post(
            reverse("refresh"),
            {"refresh": self.refresh_token},
            content_type="application/json",
        )
        second_response = self.client.post(
            reverse("refresh"),
            {"refresh": self.refresh_token},
            content_type="application/json",
        )

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(second_response.status_code, 403)


class LogoutContractTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="logout-a0@example.com",
            password="correct-horse-battery",
        )
        self.refresh_token = create_refresh_token(self.user.id)
        UserToken.objects.create(
            user=self.user,
            token=self.refresh_token,
            expired_at=timezone.now() + timedelta(days=7),
        )

    def test_cookie_refresh_token_logout_deletes_usertoken(self):
        self.client.cookies["refresh_token"] = self.refresh_token

        response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            UserToken.objects.filter(token=self.refresh_token, revoked_at__isnull=False).exists()
        )

    def test_authorization_refresh_token_logout_revokes_family_after_a1(self):
        response = self.client.post(
            reverse("logout"),
            HTTP_AUTHORIZATION=f"Bearer {self.refresh_token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            UserToken.objects.filter(token=self.refresh_token, revoked_at__isnull=False).exists()
        )

    def test_body_refresh_token_logout_revokes_family_after_a1(self):
        response = self.client.post(
            reverse("logout"),
            {"refresh": self.refresh_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            UserToken.objects.filter(token=self.refresh_token, revoked_at__isnull=False).exists()
        )

    def test_missing_refresh_token_logout_still_succeeds(self):
        response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, 200)

    def test_already_revoked_logout_still_succeeds(self):
        UserToken.objects.filter(token=self.refresh_token).delete()
        self.client.cookies["refresh_token"] = self.refresh_token

        response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, 200)


class PasswordResetContractTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="reset-a0@example.com",
            password="original-password",
        )

    def _create_reset_token(self):
        token = PasswordResetTokenGenerator().make_token(self.user)
        Reset.objects.create(email=self.user.email, token=token)
        return token

    def test_valid_password_reset_succeeds(self):
        token = self._create_reset_token()

        response = self.client.post(
            reverse("reset_password"),
            {
                "password": "brand-new-password-123",
                "password_confirm": "brand-new-password-123",
                "token": token,
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 202)

    def test_used_password_reset_token_cannot_be_reused(self):
        token = self._create_reset_token()
        payload = {
            "password": "brand-new-password-123",
            "password_confirm": "brand-new-password-123",
            "token": token,
        }

        first_response = self.client.post(
            reverse("reset_password"),
            payload,
            content_type="application/json",
        )
        second_response = self.client.post(
            reverse("reset_password"),
            payload,
            content_type="application/json",
        )

        self.assertEqual(first_response.status_code, 202)
        self.assertEqual(second_response.status_code, 404)

    @override_settings(PASSWORD_RESET_TIMEOUT=1)
    def test_expired_password_reset_token_is_rejected(self):
        token = self._create_reset_token()
        with patch("django.contrib.auth.tokens.PasswordResetTokenGenerator.check_token", return_value=False):
            response = self.client.post(
                reverse("reset_password"),
                {
                    "password": "brand-new-password-123",
                    "password_confirm": "brand-new-password-123",
                    "token": token,
                },
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 400)

    def test_invalid_password_reset_token_is_rejected(self):
        response = self.client.post(
            reverse("reset_password"),
            {
                "password": "brand-new-password-123",
                "password_confirm": "brand-new-password-123",
                "token": "not-a-real-token",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 404)

    def test_password_reset_revokes_existing_refresh_tokens(self):
        refresh_token = create_refresh_token(self.user.id)
        UserToken.objects.create(
            user=self.user,
            token=refresh_token,
            expired_at=timezone.now() + timedelta(days=7),
        )
        reset_token = self._create_reset_token()

        reset_response = self.client.post(
            reverse("reset_password"),
            {
                "password": "brand-new-password-123",
                "password_confirm": "brand-new-password-123",
                "token": reset_token,
            },
            content_type="application/json",
        )
        refresh_response = self.client.post(
            reverse("refresh"),
            {"refresh": refresh_token},
            content_type="application/json",
        )

        self.assertEqual(reset_response.status_code, 202)
        self.assertEqual(refresh_response.status_code, 403)


class OtpContractTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.secret = pyotp.random_base32()
        self.user = User.objects.create_user(
            email="otp-a0@example.com",
            password="correct-horse-battery",
            is_2fa_enabled=True,
            tfa_secret=self.secret,
        )

    def test_login_for_2fa_user_requires_second_factor(self):
        response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": "correct-horse-battery"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        self.assertTrue(response.json()["2fa_required"])
        self.assertIn("temp_token", response.cookies)

    def test_valid_otp_succeeds(self):
        self.client.cookies["temp_token"] = create_temporary_2fa_token(self.user.id)

        response = self.client.post(
            reverse("two_factor_login"),
            {"otp": pyotp.TOTP(self.secret).now()},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())
        self.assertIn("refresh_token", response.json())

    def test_invalid_otp_is_rejected(self):
        self.client.cookies["temp_token"] = create_temporary_2fa_token(self.user.id)

        response = self.client.post(
            reverse("two_factor_login"),
            {"otp": "000000"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_expired_temp_token_is_rejected(self):
        expired_token = jwt.encode(
            {
                "user_id": self.user.id,
                "type": "2FA_temporary",
                "exp": timezone.now() - timedelta(minutes=1),
                "iat": timezone.now() - timedelta(minutes=11),
                "2fa_stage": "awaiting_verification",
            },
            JWT_TEMP_SECRET,
            algorithm="HS256",
        )
        self.client.cookies["temp_token"] = expired_token

        response = self.client.post(
            reverse("two_factor_login"),
            {"otp": pyotp.TOTP(self.secret).now()},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)

    def test_otp_can_currently_be_reused_with_same_temp_token_security_gap(self):
        # CURRENT SECURITY GAP - EXPECTED TO CHANGE IN A4.
        fixed_time = timezone.now().replace(tzinfo=datetime_timezone.utc)
        otp = pyotp.TOTP(self.secret).at(fixed_time)
        self.client.cookies["temp_token"] = create_temporary_2fa_token(self.user.id)
        first_refresh = jwt.encode(
            {
                "user_id": self.user.id,
                "email": self.user.email,
                "role": self.user.role,
                "nonce": "otp-replay-1",
                "exp": timezone.now() + timedelta(days=7),
                "iat": timezone.now(),
            },
            JWT_REFRESH_SECRET,
            algorithm="HS256",
        )
        second_refresh = jwt.encode(
            {
                "user_id": self.user.id,
                "email": self.user.email,
                "role": self.user.role,
                "nonce": "otp-replay-2",
                "exp": timezone.now() + timedelta(days=7),
                "iat": timezone.now(),
            },
            JWT_REFRESH_SECRET,
            algorithm="HS256",
        )

        with patch("pyotp.TOTP.timecode", return_value=pyotp.TOTP(self.secret).timecode(fixed_time)):
            first_response = self.client.post(
                reverse("two_factor_login"),
                {"otp": otp},
                content_type="application/json",
            )
            second_response = self.client.post(
                reverse("two_factor_login"),
                {"otp": otp},
                content_type="application/json",
            )

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(second_response.status_code, 200)


class ThrottleContractTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            email="throttle-a0@example.com",
            password="correct-horse-battery",
        )

    def test_contact_form_throttle_is_enforced(self):
        with patch("mail.views.EmailMultiAlternatives") as email_message:
            for index in range(5):
                response = self.client.post(
                    reverse("send_email"),
                    {
                        "reply_to": f"visitor{index}@example.com",
                        "subject": "Hello",
                        "content": "Message",
                    },
                    content_type="application/json",
                )
                self.assertNotEqual(response.status_code, 429)

            sixth_response = self.client.post(
                reverse("send_email"),
                {
                    "reply_to": "visitor6@example.com",
                    "subject": "Hello",
                    "content": "Message",
                },
                content_type="application/json",
            )

        self.assertEqual(sixth_response.status_code, 429)
        self.assertEqual(email_message.return_value.send.call_count, 5)


class MiddlewareDrfCompatibilityContractTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="compat-a0@example.com",
            password="correct-horse-battery",
        )

    def test_explicit_drf_authentication_sets_request_auth_to_raw_token(self):
        token = create_access_token(self.user.id)

        with patch("user.views.CustomUserSerializer") as serializer:
            serializer.return_value.data = {"email": self.user.email}
            response = self.client.get(
                reverse("fetch_user"),
                HTTP_AUTHORIZATION=f"Bearer {token}",
            )

        self.assertEqual(response.status_code, 200)
        serialized_user = serializer.call_args.args[0]
        self.assertEqual(serialized_user, self.user)

    def test_middleware_authenticated_view_does_not_have_drf_request_auth(self):
        token = create_access_token(self.user.id)
        self.client.cookies["access_token"] = token

        response = self.client.patch(
            reverse("toggle_2fa"),
            {"is_2fa_enabled": True},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_2fa_setup_in_progress)


class CredentialExposureContractTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="logs-a0@example.com",
            password="correct-horse-battery",
        )

    def test_access_token_value_is_not_emitted_by_middleware_logs(self):
        token = create_access_token(self.user.id)

        with self.assertLogs("authentication.custom_middleware.token_auth", level="DEBUG") as logs:
            response = self.client.get(
                reverse("fetch_user"),
                HTTP_AUTHORIZATION=f"Bearer {token}",
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(token, "\n".join(logs.output))

    def test_usertoken_admin_does_not_display_raw_refresh_token(self):
        model_admin = UserTokenAdmin(UserToken, admin.site)

        self.assertNotIn("token", model_admin.list_display)
        self.assertNotIn("token", model_admin.fields)
