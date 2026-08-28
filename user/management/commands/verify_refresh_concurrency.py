# Filename: user/management/commands/verify_refresh_concurrency.py
"""Verify refresh-token rotation locking against the active database."""

from __future__ import annotations

import threading
import uuid

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections
from django.utils import timezone

from user.models import UserToken
from user.refresh_tokens import issue_refresh_token, rotate_refresh_token


class Command(BaseCommand):
    help = (
        "Runs a staging-safe PostgreSQL concurrency check for refresh-token "
        "rotation using temporary records."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--keep-records",
            action="store_true",
            help="Leave temporary user/token rows in place for manual inspection.",
        )

    def handle(self, *args, **options):
        User = get_user_model()
        email = f"refresh-concurrency-{uuid.uuid4()}@example.invalid"
        user = User.objects.create_user(
            email=email,
            password=str(uuid.uuid4()),
        )
        issued = issue_refresh_token(user)
        family_id = issued.record.family_id
        token = issued.token
        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def rotate(label):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                rotated = rotate_refresh_token(token)
                result = {
                    "label": label,
                    "status": "success",
                    "new_jti": str(rotated.new_record.jti),
                }
            except Exception as exc:  # noqa: BLE001 - command reports exact outcome.
                result = {
                    "label": label,
                    "status": "failure",
                    "error_type": exc.__class__.__name__,
                }
            finally:
                close_old_connections()

            with lock:
                results.append(result)

        threads = [
            threading.Thread(target=rotate, args=("request_1",)),
            threading.Thread(target=rotate, args=("request_2",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        if any(thread.is_alive() for thread in threads):
            raise CommandError("Concurrency verification timed out.")

        records = list(UserToken.objects.filter(family_id=family_id).order_by("created_at"))
        success_count = sum(1 for result in results if result["status"] == "success")
        failure_count = sum(1 for result in results if result["status"] == "failure")
        replacement_count = sum(1 for record in records if record.jti != issued.record.jti)
        active_count = sum(
            1
            for record in records
            if not record.consumed_at and not record.is_revoked and not record.revoked_at
        )
        original = UserToken.objects.get(pk=issued.record.pk)

        self.stdout.write(f"family_id={family_id}")
        self.stdout.write(f"results={results}")
        self.stdout.write(f"success_count={success_count}")
        self.stdout.write(f"failure_count={failure_count}")
        self.stdout.write(f"family_record_count={len(records)}")
        self.stdout.write(f"replacement_count={replacement_count}")
        self.stdout.write(f"active_count={active_count}")
        self.stdout.write(f"original_consumed={bool(original.consumed_at)}")
        self.stdout.write(
            "family_revoked="
            f"{all(record.is_revoked and record.revoked_at for record in records)}"
        )
        self.stdout.write(
            "revocation_reasons="
            f"{sorted({record.revocation_reason for record in records})}"
        )

        ok = (
            success_count == 1
            and failure_count == 1
            and replacement_count == 1
            and bool(original.consumed_at)
            and all(record.is_revoked and record.revoked_at for record in records)
        )

        if not options["keep_records"]:
            UserToken.objects.filter(family_id=family_id).delete()
            user.delete()

        if not ok:
            raise CommandError(
                "Refresh-token concurrency invariant failed at "
                f"{timezone.now().isoformat()}."
            )

        self.stdout.write(self.style.SUCCESS("Refresh-token concurrency invariant passed."))
