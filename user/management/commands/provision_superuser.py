from __future__ import annotations

import os

from django.core.management.base import BaseCommand, CommandError

from user.models import CustomUser


class Command(BaseCommand):
    help = "Create or update a superuser account from a password hash."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="Superuser email address.")
        parser.add_argument(
            "--password-hash-env",
            required=True,
            help="Environment variable that contains the Django password hash.",
        )
        parser.add_argument(
            "--staff",
            action="store_true",
            default=True,
            help="Ensure is_staff is enabled.",
        )
        parser.add_argument(
            "--superuser",
            action="store_true",
            default=True,
            help="Ensure is_superuser is enabled.",
        )

    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        password_hash_env = options["password_hash_env"]
        password_hash = os.getenv(password_hash_env)
        if not password_hash:
            raise CommandError(
                f"Environment variable {password_hash_env!r} is required and cannot be empty."
            )

        user, created = CustomUser.objects.update_or_create(
            email=email,
            defaults={
                "password": password_hash,
                "is_staff": bool(options["staff"]),
                "is_superuser": bool(options["superuser"]),
                "is_active": True,
            },
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"{'Created' if created else 'Updated'} superuser {user.email}"
            )
        )
