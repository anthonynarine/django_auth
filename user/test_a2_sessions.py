# Filename: user/test_a2_sessions.py
"""A2 regression tests for authenticated session enforcement."""

from datetime import timedelta

import jwt
import pyotp
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from user.auth_token import JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, create_access_token, create_refresh_token, create_temporary_2fa_token
from user.models import Reset, AuthSession, UserToken

User = get_user_model()


def _decode_access(token: str) -> dict:
    return jwt.decode(token, JWT_ACCESS_SECRET, algorithms=["HS256"])


def _decode_refresh(token: str) -> dict:
    return jwt.decode(token, JWT_REFRESH_SECRET, algorithms=["HS256"])


class AuthSessionLifecycleTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.password = "correct-horse-battery"
        self.user = User.objects.create_user(
            email="session@example.com",
            password=self.password,
        )

    def test_login_creates_auth_session_and_sid_bound_tokens(self):
        response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        access_payload = _decode_access(response.json()["access_token"])
        refresh_payload = _decode_refresh(response.json()["refresh_token"])

        self.assertIn("sid", access_payload)
        self.assertEqual(access_payload["sid"], refresh_payload["sid"])

        session = AuthSession.objects.get(id=access_payload["sid"])
        self.assertEqual(session.user, self.user)
        self.assertIsNone(session.revoked_at)
        self.assertEqual(session.id, UserToken.objects.get(user=self.user).auth_session_id)

    def test_validate_session_exposes_is_staff_for_staff_users(self):
        staff = User.objects.create_user(
            email="staff-session@example.com",
            password=self.password,
            is_staff=True,
        )
        login_response = self.client.post(
            reverse("login"),
            {"email": staff.email, "password": self.password},
            content_type="application/json",
        )
        access_token = login_response.json()["access_token"]

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {access_token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["is_staff"])

    def test_validate_session_exposes_is_staff_false_for_non_staff_users(self):
        login_response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        access_token = login_response.json()["access_token"]

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {access_token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["is_staff"])

    def test_refresh_preserves_session_identifier_and_migrates_family_state(self):
        login_response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        refresh_token = login_response.json()["refresh_token"]
        original_access_payload = _decode_access(login_response.json()["access_token"])

        response = self.client.post(
            reverse("refresh"),
            {"refresh": refresh_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        new_access_payload = _decode_access(response.json()["access_token"])
        new_refresh_payload = _decode_refresh(response.json()["refresh_token"])

        self.assertEqual(original_access_payload["sid"], new_access_payload["sid"])
        self.assertEqual(original_access_payload["sid"], new_refresh_payload["sid"])

        session = AuthSession.objects.get(id=original_access_payload["sid"])
        self.assertEqual(UserToken.objects.filter(auth_session=session).count(), 2)
        self.assertTrue(UserToken.objects.filter(auth_session=session, consumed_at__isnull=False).exists())

    def test_refresh_replay_revokes_associated_session(self):
        login_response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        access_token = login_response.json()["access_token"]
        refresh_token = login_response.json()["refresh_token"]
        sid = _decode_access(access_token)["sid"]

        first_refresh = self.client.post(
            reverse("refresh"),
            {"refresh": refresh_token},
            content_type="application/json",
        )
        self.assertEqual(first_refresh.status_code, 200)

        replay_response = self.client.post(
            reverse("refresh"),
            {"refresh": refresh_token},
            content_type="application/json",
        )
        self.assertEqual(replay_response.status_code, 403)

        session = AuthSession.objects.get(id=sid)
        self.assertIsNotNone(session.revoked_at)

        protected_response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {access_token}",
        )
        self.assertEqual(protected_response.status_code, 401)

    def test_logout_revokes_session_and_existing_access_token_fails(self):
        login_response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        access_token = login_response.json()["access_token"]
        refresh_token = login_response.json()["refresh_token"]
        sid = _decode_access(access_token)["sid"]

        response = self.client.post(
            reverse("logout"),
            {"refresh": refresh_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        session = AuthSession.objects.get(id=sid)
        self.assertIsNotNone(session.revoked_at)

        protected_response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {access_token}",
        )
        self.assertEqual(protected_response.status_code, 401)

    def test_logout_all_revokes_every_session_for_user(self):
        first_login = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        second_login = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )

        first_access = first_login.json()["access_token"]
        second_access = second_login.json()["access_token"]

        response = self.client.post(
            reverse("logout_all"),
            HTTP_AUTHORIZATION=f"Bearer {first_access}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            AuthSession.objects.filter(user=self.user, revoked_at__isnull=True).exists()
        )

        protected_response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {second_access}",
        )
        self.assertEqual(protected_response.status_code, 401)

    def test_inactive_user_with_sid_bound_token_is_rejected(self):
        login_response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        access_token = login_response.json()["access_token"]

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {access_token}",
        )

        self.assertEqual(response.status_code, 401)


class TwoFactorAuthSessionTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.secret = pyotp.random_base32()
        self.user = User.objects.create_user(
            email="session-2fa@example.com",
            password="correct-horse-battery",
            is_2fa_enabled=True,
            tfa_secret=self.secret,
        )

    def test_two_factor_login_creates_session_bound_tokens(self):
        self.client.cookies["temp_token"] = create_temporary_2fa_token(self.user.id)

        response = self.client.post(
            reverse("two_factor_login"),
            {"otp": pyotp.TOTP(self.secret).now()},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        access_payload = _decode_access(response.json()["access_token"])
        refresh_payload = _decode_refresh(response.json()["refresh_token"])
        self.assertIn("sid", access_payload)
        self.assertEqual(access_payload["sid"], refresh_payload["sid"])

        session = AuthSession.objects.get(id=access_payload["sid"])
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.authentication_strength, "mfa")


class LegacyAccessCompatibilityTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            email="legacy-access@example.com",
            password="correct-horse-battery",
        )

    def test_legacy_access_token_without_sid_is_allowed_during_observe_window(self):
        legacy_token = create_access_token(self.user.id)

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {legacy_token}",
        )

        self.assertEqual(response.status_code, 200)

    @override_settings(AUTH_SESSION_ENFORCEMENT="ENFORCE")
    def test_legacy_access_token_without_sid_is_rejected_when_enforced(self):
        legacy_token = create_access_token(self.user.id)

        response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {legacy_token}",
        )

        self.assertEqual(response.status_code, 401)


class PasswordResetSessionRevocationTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.password = "correct-horse-battery"
        self.user = User.objects.create_user(
            email="reset-session@example.com",
            password=self.password,
        )

    def _create_reset_token(self):
        self.user.refresh_from_db()
        token = PasswordResetTokenGenerator().make_token(self.user)
        Reset.objects.create(email=self.user.email, token=token)
        return token

    def test_password_reset_revokes_existing_sessions(self):
        login_response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        access_token = login_response.json()["access_token"]
        sid = _decode_access(access_token)["sid"]

        response = self.client.post(
            reverse("reset_password"),
            {
                "password": "brand-new-password-123",
                "password_confirm": "brand-new-password-123",
                "token": self._create_reset_token(),
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 202)
        session = AuthSession.objects.get(id=sid)
        self.assertIsNotNone(session.revoked_at)

        protected_response = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {access_token}",
        )
        self.assertEqual(protected_response.status_code, 401)


class LegacyRefreshSessionMigrationTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            email="legacy-refresh-session@example.com",
            password="correct-horse-battery",
        )
        self.legacy_refresh = create_refresh_token(self.user.id)
        self.legacy_record = UserToken.objects.create(
            user=self.user,
            token=self.legacy_refresh,
            expired_at=timezone.now() + timedelta(days=7),
        )

    def test_legacy_refresh_token_creates_auth_session_on_first_refresh(self):
        response = self.client.post(
            reverse("refresh"),
            {"refresh": self.legacy_refresh},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.legacy_record.refresh_from_db()
        self.assertIsNotNone(self.legacy_record.auth_session_id)

        access_payload = _decode_access(response.json()["access_token"])
        refresh_payload = _decode_refresh(response.json()["refresh_token"])
        self.assertEqual(access_payload["sid"], str(self.legacy_record.auth_session_id))
        self.assertEqual(refresh_payload["sid"], access_payload["sid"])
