# Filename: user/test_a1_refresh_lifecycle.py
"""A1 regression tests for refresh-token lifecycle hardening."""

from datetime import timedelta
from uuid import uuid4

import jwt
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import Client, TestCase, TransactionTestCase, skipUnlessDBFeature
from django.urls import reverse
from django.utils import timezone

from user.auth_token import JWT_REFRESH_SECRET, create_refresh_token
from user.models import UserToken
from user.refresh_tokens import (
    hash_refresh_token,
    issue_refresh_token,
    rotate_refresh_token,
)

User = get_user_model()


class RefreshRotationLifecycleTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="a1-refresh@example.com",
            password="correct-horse-battery",
        )

    def test_login_issues_hardened_refresh_token_without_raw_storage(self):
        response = self.client.post(
            reverse("login"),
            {"email": self.user.email, "password": "correct-horse-battery"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        refresh_token = response.json()["refresh_token"]
        record = UserToken.objects.get(user=self.user)
        payload = jwt.decode(refresh_token, JWT_REFRESH_SECRET, algorithms=["HS256"])
        self.assertEqual(payload["type"], "refresh")
        self.assertEqual(str(record.jti), payload["jti"])
        self.assertEqual(str(record.family_id), payload["family_id"])
        self.assertIsNone(record.token)
        self.assertEqual(record.token_hash, hash_refresh_token(refresh_token))

    def test_valid_refresh_token_rotates_and_returns_replacement_token(self):
        issued = issue_refresh_token(self.user)

        response = self.client.post(
            reverse("refresh"),
            {"refresh": issued.token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())
        self.assertIn("refresh_token", response.json())
        issued.record.refresh_from_db()
        replacement = UserToken.objects.get(jti=issued.record.replaced_by_jti)
        self.assertIsNotNone(issued.record.consumed_at)
        self.assertEqual(replacement.family_id, issued.record.family_id)
        self.assertNotEqual(replacement.jti, issued.record.jti)

    def test_consumed_refresh_token_cannot_refresh_again(self):
        issued = issue_refresh_token(self.user)
        first_response = self.client.post(
            reverse("refresh"),
            {"refresh": issued.token},
            content_type="application/json",
        )
        second_response = self.client.post(
            reverse("refresh"),
            {"refresh": issued.token},
            content_type="application/json",
        )

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(second_response.status_code, 403)

    def test_replay_revokes_family_and_replacement_becomes_unusable(self):
        issued = issue_refresh_token(self.user)
        first_response = self.client.post(
            reverse("refresh"),
            {"refresh": issued.token},
            content_type="application/json",
        )
        replacement_token = first_response.json()["refresh_token"]

        replay_response = self.client.post(
            reverse("refresh"),
            {"refresh": issued.token},
            content_type="application/json",
        )
        replacement_response = self.client.post(
            reverse("refresh"),
            {"refresh": replacement_token},
            content_type="application/json",
        )

        self.assertEqual(replay_response.status_code, 403)
        self.assertEqual(replacement_response.status_code, 403)
        self.assertFalse(
            UserToken.objects.filter(
                family_id=issued.record.family_id,
                revoked_at__isnull=True,
            ).exists()
        )

    def test_replay_does_not_revoke_unrelated_family(self):
        first_family = issue_refresh_token(self.user)
        second_family = issue_refresh_token(self.user)

        self.client.post(
            reverse("refresh"),
            {"refresh": first_family.token},
            content_type="application/json",
        )
        self.client.post(
            reverse("refresh"),
            {"refresh": first_family.token},
            content_type="application/json",
        )
        unrelated_response = self.client.post(
            reverse("refresh"),
            {"refresh": second_family.token},
            content_type="application/json",
        )

        self.assertEqual(unrelated_response.status_code, 200)

    def test_jti_uniqueness_is_enforced(self):
        shared_jti = uuid4()
        UserToken.objects.create(
            user=self.user,
            token_hash="a" * 64,
            jti=shared_jti,
            family_id=uuid4(),
            expired_at=timezone.now() + timedelta(days=7),
        )

        with self.assertRaises(IntegrityError):
            UserToken.objects.create(
                user=self.user,
                token_hash="b" * 64,
                jti=shared_jti,
                family_id=uuid4(),
                expired_at=timezone.now() + timedelta(days=7),
            )


class LegacyRefreshMigrationTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="legacy-a1@example.com",
            password="correct-horse-battery",
        )
        self.legacy_token = create_refresh_token(self.user.id)
        self.legacy_record = UserToken.objects.create(
            user=self.user,
            token=self.legacy_token,
            expired_at=timezone.now() + timedelta(days=7),
        )

    def test_legacy_raw_refresh_token_rotates_into_hardened_token(self):
        response = self.client.post(
            reverse("refresh"),
            {"refresh": self.legacy_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.legacy_record.refresh_from_db()
        replacement = UserToken.objects.get(jti=self.legacy_record.replaced_by_jti)
        self.assertIsNotNone(self.legacy_record.consumed_at)
        self.assertEqual(self.legacy_record.token_hash, hash_refresh_token(self.legacy_token))
        self.assertIsNone(replacement.token)
        self.assertIsNotNone(replacement.token_hash)

    def test_legacy_token_reuse_after_migration_is_replay_and_fails(self):
        self.client.post(
            reverse("refresh"),
            {"refresh": self.legacy_token},
            content_type="application/json",
        )

        response = self.client.post(
            reverse("refresh"),
            {"refresh": self.legacy_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)


class RefreshRevocationTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="revocation-a1@example.com",
            password="correct-horse-battery",
        )

    def test_revoked_refresh_token_fails(self):
        issued = issue_refresh_token(self.user)
        issued.record.is_revoked = True
        issued.record.revoked_at = timezone.now()
        issued.record.revocation_reason = "TEST"
        issued.record.save(update_fields=["is_revoked", "revoked_at", "revocation_reason"])

        response = self.client.post(
            reverse("refresh"),
            {"refresh": issued.token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_logout_revokes_refresh_token_family(self):
        issued = issue_refresh_token(self.user)

        response = self.client.post(
            reverse("logout"),
            {"refresh": issued.token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            UserToken.objects.filter(
                family_id=issued.record.family_id,
                revoked_at__isnull=True,
            ).exists()
        )


@skipUnlessDBFeature("has_select_for_update")
class RefreshRotationConcurrencyTest(TransactionTestCase):
    reset_sequences = True

    def test_same_refresh_token_can_only_rotate_once_under_row_locking(self):
        user = User.objects.create_user(
            email="concurrency-a1@example.com",
            password="correct-horse-battery",
        )
        issued = issue_refresh_token(user)

        first = rotate_refresh_token(issued.token)
        with self.assertRaises(Exception):
            rotate_refresh_token(issued.token)

        issued.record.refresh_from_db()
        self.assertIsNotNone(first.refresh_token)
        self.assertIsNotNone(issued.record.consumed_at)
