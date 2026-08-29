# Generated for A2 authenticated-session support.

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("user", "0016_refresh_token_lifecycle_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuthSession",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        verbose_name="Session ID",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Created At")),
                ("last_seen_at", models.DateTimeField(default=django.utils.timezone.now, verbose_name="Last Seen At")),
                ("expires_at", models.DateTimeField(verbose_name="Expires At")),
                ("revoked_at", models.DateTimeField(blank=True, null=True, verbose_name="Revoked At")),
                ("revocation_reason", models.CharField(blank=True, default="", max_length=64, verbose_name="Revocation Reason")),
                ("authentication_method", models.CharField(default="password", max_length=32, verbose_name="Authentication Method")),
                ("authentication_strength", models.CharField(default="password", max_length=32, verbose_name="Authentication Strength")),
                ("recent_auth_at", models.DateTimeField(default=django.utils.timezone.now, verbose_name="Recent Auth At")),
                ("created_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("last_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True, default="")),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="auth_sessions",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="User",
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["user", "revoked_at"], name="user_authses_user_revoked_idx"),
                    models.Index(fields=["expires_at"], name="user_authses_expires_idx"),
                ],
            },
        ),
        migrations.AddField(
            model_name="usertoken",
            name="auth_session",
            field=models.ForeignKey(
                blank=True,
                help_text="Server-controlled session that owns this refresh token.",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="refresh_tokens",
                to="user.authsession",
                verbose_name="Auth Session",
            ),
        ),
        migrations.AddIndex(
            model_name="usertoken",
            index=models.Index(fields=["auth_session", "revoked_at"], name="user_userto_sess_revoked_idx"),
        ),
    ]
