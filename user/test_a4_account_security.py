"""A4 account and authentication hardening tests."""

from datetime import timedelta

import pyotp
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.cache import cache
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from security.models import SecurityEvent
from user.account_security_services import is_recent_auth, mark_account_disabled
from user.auth_token import create_temporary_2fa_token
from user.models import AuthSession

User = get_user_model()


@override_settings(RECENT_AUTH_MAX_AGE_SECONDS=600, AUTH_SESSION_ENFORCEMENT="ENFORCE")
class PasswordChangeAndReauthTest(TransactionTestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.password = "correct-horse-battery"
        self.new_password = "brand-new-password"
        self.user = User.objects.create_user(
            email="a4-password@example.com",
            password=self.password,
        )

    def _login(self):
        response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_password_change_requires_current_password_and_revokes_other_sessions(self):
        first_login = self._login()
        second_login = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(second_login.status_code, 200)

        response = self.client.post(
            reverse("change_password"),
            {
                "current_password": self.password,
                "new_password": self.new_password,
                "new_password_confirm": self.new_password,
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {first_login['access_token']}",
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password(self.password))
        self.assertTrue(self.user.check_password(self.new_password))
        failed_login = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(failed_login.status_code, 401)
        self.assertEqual(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EventType.PASSWORD_CHANGE_SUCCESS,
            ).count(),
            1,
        )
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EventType.SESSION_REVOKED,
                reason_code="PASSWORD_CHANGE",
            ).exists()
        )

        old_access = second_login.json()["access_token"]
        protected = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {old_access}",
        )
        self.assertEqual(protected.status_code, 401)

    def test_password_change_rejects_wrong_current_password(self):
        login = self._login()
        response = self.client.post(
            reverse("change_password"),
            {
                "current_password": "wrong-password",
                "new_password": self.new_password,
                "new_password_confirm": self.new_password,
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.user.check_password(self.password))
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE,
                reason_code="CURRENT_PASSWORD_INVALID",
            ).exists()
        )

    def test_password_change_rejects_policy_violating_password(self):
        login = self._login()
        response = self.client.post(
            reverse("change_password"),
            {
                "current_password": self.password,
                "new_password": "short",
                "new_password_confirm": "short",
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.user.check_password(self.password))
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EventType.PASSWORD_CHANGE_FAILURE,
                reason_code="PASSWORD_POLICY_REJECTED",
            ).exists()
        )

    def test_reauthenticate_updates_recent_auth_without_creating_session(self):
        login = self._login()
        session = AuthSession.objects.get(user=self.user)
        before = session.recent_auth_at

        response = self.client.post(
            reverse("reauthenticate"),
            {"current_password": self.password},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
        )

        self.assertEqual(response.status_code, 200)
        session.refresh_from_db()
        self.assertGreaterEqual(session.recent_auth_at, before)
        self.assertEqual(AuthSession.objects.filter(user=self.user).count(), 1)
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EventType.REAUTH_SUCCESS,
            ).exists()
        )

    def test_recent_auth_helper_boundary(self):
        login = self._login()
        session = AuthSession.objects.get(user=self.user)
        session.recent_auth_at = timezone.now() - timedelta(seconds=599)
        session.save(update_fields=["recent_auth_at"])
        self.assertTrue(is_recent_auth(session, max_age_seconds=600))
        session.recent_auth_at = timezone.now() - timedelta(seconds=601)
        session.save(update_fields=["recent_auth_at"])
        self.assertFalse(is_recent_auth(session, max_age_seconds=600))

    def test_reauth_failure_does_not_update_recent_auth(self):
        login = self._login()
        session = AuthSession.objects.get(user=self.user)
        before = session.recent_auth_at

        response = self.client.post(
            reverse("reauthenticate"),
            {"current_password": "wrong-password"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {login['access_token']}",
        )

        self.assertEqual(response.status_code, 400)
        session.refresh_from_db()
        self.assertEqual(session.recent_auth_at, before)
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EventType.REAUTH_FAILURE,
                reason_code="CURRENT_PASSWORD_INVALID",
            ).exists()
        )


@override_settings(RECENT_AUTH_MAX_AGE_SECONDS=600, AUTH_SESSION_ENFORCEMENT="ENFORCE")
class RecentAuthAndMfaTest(TransactionTestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.password = "correct-horse-battery"

    def _create_mfa_user(self, email: str):
        secret = pyotp.random_base32()
        return User.objects.create_user(
            email=email,
            password=self.password,
            is_2fa_enabled=True,
            tfa_secret=secret,
        ), secret

    def test_recent_auth_required_for_qr_generation(self):
        user = User.objects.create_user(email="recent-auth@example.com", password=self.password)
        login = self.client.post(
            reverse("login"),
            {"email": user.email, "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(login.status_code, 200)
        session = AuthSession.objects.get(user=user)
        session.recent_auth_at = timezone.now() - timedelta(seconds=3600)
        session.save(update_fields=["recent_auth_at"])

        response = self.client.get(
            reverse("generate_qr_code"),
            HTTP_AUTHORIZATION=f"Bearer {login.json()['access_token']}",
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.MFA_CHANGE_DENIED,
                reason_code="RECENT_AUTH_REQUIRED",
            ).exists()
        )

    def test_disable_mfa_requires_password_and_otp_and_revokes_other_sessions(self):
        user, secret = self._create_mfa_user("disable-mfa@example.com")
        self.client.cookies["temp_token"] = create_temporary_2fa_token(user.id)
        first_login = self.client.post(
            reverse("two_factor_login"),
            {"otp": pyotp.TOTP(secret).now()},
            content_type="application/json",
        )
        self.assertEqual(first_login.status_code, 200)
        self.client.cookies["temp_token"] = create_temporary_2fa_token(user.id)
        second_login = self.client.post(
            reverse("two_factor_login"),
            {"otp": pyotp.TOTP(secret).now()},
            content_type="application/json",
        )
        self.assertEqual(second_login.status_code, 200)

        response = self.client.patch(
            reverse("toggle_2fa"),
            {
                "is_2fa_enabled": False,
                "current_password": self.password,
                "otp": pyotp.TOTP(secret).now(),
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {first_login.json()['access_token']}",
        )

        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertFalse(user.is_2fa_enabled)
        self.assertEqual(AuthSession.objects.filter(user=user, revoked_at__isnull=True).count(), 1)
        self.assertEqual(
            AuthSession.objects.filter(user=user, revoked_at__isnull=False).count(),
            1,
        )
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.MFA_DISABLED,
            ).exists()
        )
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.SESSION_REVOKED,
                reason_code="MFA_DISABLED",
            ).exists()
        )
        protected = self.client.get(
            reverse("fetch_user"),
            HTTP_AUTHORIZATION=f"Bearer {second_login.json()['access_token']}",
        )
        self.assertEqual(protected.status_code, 401)

    def test_disable_mfa_rejects_wrong_otp(self):
        user, secret = self._create_mfa_user("disable-mfa-otp@example.com")
        self.client.cookies["temp_token"] = create_temporary_2fa_token(user.id)
        login = self.client.post(
            reverse("two_factor_login"),
            {"otp": pyotp.TOTP(secret).now()},
            content_type="application/json",
        )
        self.assertEqual(login.status_code, 200)

        response = self.client.patch(
            reverse("toggle_2fa"),
            {
                "is_2fa_enabled": False,
                "current_password": self.password,
                "otp": "000000",
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {login.json()['access_token']}",
        )

        self.assertEqual(response.status_code, 400)
        user.refresh_from_db()
        self.assertTrue(user.is_2fa_enabled)
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.MFA_CHANGE_DENIED,
                reason_code="INVALID_OTP",
            ).exists()
        )

    def test_enable_mfa_records_enabled_event(self):
        user = User.objects.create_user(email="enable-ready@example.com", password=self.password)
        login = self.client.post(
            reverse("login"),
            {"email": user.email, "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(login.status_code, 200)

        toggle = self.client.patch(
            reverse("toggle_2fa"),
            {"is_2fa_enabled": True},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {login.json()['access_token']}",
        )
        self.assertEqual(toggle.status_code, 200)

        qr = self.client.get(
            reverse("generate_qr_code"),
            HTTP_AUTHORIZATION=f"Bearer {login.json()['access_token']}",
        )
        self.assertEqual(qr.status_code, 200)
        user.refresh_from_db()
        otp = pyotp.TOTP(user.tfa_secret).now()

        verify = self.client.post(
            reverse("verify_2fa_setup"),
            {"otp": otp},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {login.json()['access_token']}",
        )
        self.assertEqual(verify.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.is_2fa_enabled)
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=user,
                event_type=SecurityEvent.EventType.MFA_ENABLED,
            ).exists()
        )

    def test_enable_mfa_requires_recent_auth(self):
        user = User.objects.create_user(email="enable-mfa@example.com", password=self.password)
        login = self.client.post(
            reverse("login"),
            {"email": user.email, "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(login.status_code, 200)
        session = AuthSession.objects.get(user=user)
        session.recent_auth_at = timezone.now() - timedelta(seconds=3600)
        session.save(update_fields=["recent_auth_at"])

        response = self.client.get(
            reverse("generate_qr_code"),
            HTTP_AUTHORIZATION=f"Bearer {login.json()['access_token']}",
        )
        self.assertEqual(response.status_code, 403)


@override_settings(RECENT_AUTH_MAX_AGE_SECONDS=600, AUTH_SESSION_ENFORCEMENT="ENFORCE")
class AccountDisableAuditTest(TransactionTestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.password = "correct-horse-battery"
        self.user = User.objects.create_user(
            email="disabled@example.com",
            password=self.password,
        )

    def test_admin_disable_revokes_sessions_and_records_event(self):
        login = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(login.status_code, 200)

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        mark_account_disabled(user=self.user)

        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertFalse(AuthSession.objects.filter(user=self.user, revoked_at__isnull=True).exists())
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EventType.ACCOUNT_DISABLED,
            ).exists()
        )
