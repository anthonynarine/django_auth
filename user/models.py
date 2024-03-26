# Standard library imports
from enum import unique

# Third-party imports
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

# Local application/library specific imports
from .manager import CustomUserManager

class CustomUser(AbstractUser):
    first_name = models.CharField(max_length=26)
    last_name = models.CharField(max_length=26)
    email = models.EmailField(_("email address"), unique=True)
    password = models.CharField(max_length=100)
    username = None
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    
    objects = CustomUserManager()
    
    
class UserToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        help_text="The user to whom this token is assigned.")
    token = models.CharField(
        max_length=512,
        unique=True,
        help_text="The unique token string."
        )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="The datetime when this token was created."
        )
    expired_at = models.DateField(help_text="The date when this token will expire."
        )
    is_revoked = models.BooleanField(
        default=False,
        help_text="Flag indicating whether the token has been manually revoked."
        )
    last_used_at = models.DateTimeField(
        auto_now=True,
        help_text="The last time this token was used."
        )
    
    def __str__(self):
        return f"{self.user}'s"


class Reset(models.Model):
    email = models.CharField(max_length=100)
    token = models.CharField(
        max_length=512,
        unique=True,
        help_text="The unique token string."
    )
    
    