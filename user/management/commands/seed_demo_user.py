import secrets

from django.core.management.base import BaseCommand

from user.models import CustomUser
from user.guest import DEMO_USER_EMAIL


class Command(BaseCommand):
    """
    Creates (or resets) the fixed demo account used by the "Continue as guest"
    button on the frontend. Idempotent: safe to re-run at any time, e.g. after
    a deploy, to reset the account back to a clean state.
    """

    help = "Create or reset the demo account used for guest login."

    def handle(self, *args, **options):
        user, created = CustomUser.objects.get_or_create(
            email=DEMO_USER_EMAIL,
            defaults={
                "first_name": "Guest",
                "last_name": "Visitor",
            },
        )

        # Guest login never uses this password directly (GuestLoginAPIView
        # issues tokens without checking it), but every user needs a set
        # password, and a random one ensures it can't double as a working
        # credential for the regular /login/ endpoint.
        user.set_password(secrets.token_urlsafe(32))
        user.is_2fa_enabled = False
        user.is_2fa_setup_in_progress = False
        user.tfa_secret = ""
        user.save()

        verb = "Created" if created else "Reset"
        self.stdout.write(self.style.SUCCESS(f"{verb} demo user: {DEMO_USER_EMAIL}"))
