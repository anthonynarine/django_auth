# Generated for A1 refresh-token lifecycle hardening.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user", "0015_customuser_role"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usertoken",
            name="token",
            field=models.CharField(
                blank=True,
                help_text="Legacy raw token string. New refresh tokens store only a hash.",
                max_length=512,
                null=True,
                unique=True,
                verbose_name="Token",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="token_hash",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="HMAC-SHA256 digest used to look up hardened refresh tokens.",
                max_length=64,
                null=True,
                unique=True,
                verbose_name="Token Hash",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="jti",
            field=models.UUIDField(
                blank=True,
                help_text="Unique identifier embedded in hardened refresh JWTs.",
                null=True,
                unique=True,
                verbose_name="JWT ID",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="family_id",
            field=models.UUIDField(
                blank=True,
                db_index=True,
                help_text="Identifier shared by rotated refresh tokens from one login.",
                null=True,
                verbose_name="Token Family ID",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="consumed_at",
            field=models.DateTimeField(
                blank=True,
                help_text="When this refresh token was rotated and made single-use.",
                null=True,
                verbose_name="Consumed At",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="revoked_at",
            field=models.DateTimeField(
                blank=True,
                help_text="When this refresh token was explicitly revoked.",
                null=True,
                verbose_name="Revoked At",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="revocation_reason",
            field=models.CharField(
                blank=True,
                default="",
                max_length=64,
                verbose_name="Revocation Reason",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="replaced_by_jti",
            field=models.UUIDField(
                blank=True,
                help_text="JTI of the refresh token issued when this token was consumed.",
                null=True,
                verbose_name="Replacement JWT ID",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="created_ip",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="last_used_ip",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="user_agent",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddIndex(
            model_name="usertoken",
            index=models.Index(fields=["family_id", "revoked_at"], name="user_userto_family_6cc020_idx"),
        ),
        migrations.AddIndex(
            model_name="usertoken",
            index=models.Index(fields=["user", "family_id"], name="user_userto_user_id_2217ff_idx"),
        ),
    ]
