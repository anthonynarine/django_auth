# Generated by Django 5.0.3 on 2024-03-09 03:44

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user", "0003_usertoken"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="usertoken",
            name="user_id",
        ),
        migrations.AddField(
            model_name="usertoken",
            name="is_revoked",
            field=models.BooleanField(
                default=False,
                help_text="Flag indicating whether the token has been manually revoked.",
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="last_used_at",
            field=models.DateTimeField(
                auto_now=True, help_text="The last time this token was used."
            ),
        ),
        migrations.AddField(
            model_name="usertoken",
            name="user",
            field=models.ForeignKey(
                default=False,
                help_text="The user to whom this token is assigned.",
                on_delete=django.db.models.deletion.CASCADE,
                to=settings.AUTH_USER_MODEL,
            ),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="usertoken",
            name="created_at",
            field=models.DateTimeField(
                auto_now_add=True, help_text="The datetime when this token was created."
            ),
        ),
        migrations.AlterField(
            model_name="usertoken",
            name="expired_at",
            field=models.DateField(help_text="The date when this token will expire."),
        ),
        migrations.AlterField(
            model_name="usertoken",
            name="token",
            field=models.CharField(
                help_text="The unique token string.", max_length=255, unique=True
            ),
        ),
    ]
