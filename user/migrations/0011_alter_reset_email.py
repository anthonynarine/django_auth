# Generated by Django 5.0.3 on 2024-04-01 15:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user", "0010_alter_customuser_email_alter_customuser_first_name_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="reset",
            name="email",
            field=models.CharField(max_length=255, verbose_name="Email"),
        ),
    ]
