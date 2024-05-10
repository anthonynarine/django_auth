# Standard library imports
from enum import unique
from turtle import mode

# Third-party imports
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.forms import DateTimeField
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

# Local application/library specific imports
from .manager import CustomUserManager

class CustomUser(AbstractUser):
    """
    Custom user model where email is the unique identifier for authentication
    instead of usernames.
    """
    email = models.EmailField(
        _('email address'),
        unique=True,
        help_text='Enter your email address. Used for login.'
    )
    first_name = models.CharField(
        max_length=26,
        verbose_name='First Name',
        help_text='Enter your first name.'
    )
    last_name = models.CharField(
        max_length=26,
        verbose_name='Last Name',
        help_text='Enter your last name.'
    )
    # This field is not needed 
    # password = models.CharField(
    #     max_length=255,
    #     help_text='Enter a secure password.'
    # )
    username = None  # Username is not used in this model.
    tfa_secret = models.CharField(
        max_length=255,
        default='',
        blank=True,
        help_text='Secret key for two-factor authentication. Leave blank if unsure.'
    )
    is_2fa_enabled = models.BooleanField(
        default=False,
        verbose_name='Is 2FA Enabled',
        help_text='Check this if you wish to enable two-factor authentication.'
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

class UserToken(models.Model):
    """
    Token model for storing refresh tokens for users.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        verbose_name='User',
        help_text='The user who owns this token.'
    )
    token = models.CharField(
        max_length=512,
        unique=True,
        verbose_name='Token',
        help_text='The actual token string. Must be unique.'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Created At',
        help_text='The date and time when this token was created.'
    )
    expired_at = models.DateTimeField(
        verbose_name='Expires At',
        help_text='The date and time when this token will expire.'
    )
    is_revoked = models.BooleanField(
        default=False,
        verbose_name='Is Revoked',
        help_text='Indicates whether this token has been revoked.'
    )
    last_used_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Last Used At',
        help_text='The last date and time this token was used.'
    )

    def __str__(self):
        return f"Token for {self.user}"

class Reset(models.Model):
    """
    Model for storing reset tokens for password reset functionality.
    """
    email = models.CharField(
        max_length=255,
        verbose_name='Email'
    )
    token = models.CharField(
        max_length=512,
        unique=True,
        verbose_name='Token'
    )

    def __str__(self):
        return f"Reset token for {self.email}"

class TemporarySecurityToken(models.Model):
    """
    Temporary security token for 2FA setup or other temporary access needs.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        verbose_name=_('User'),
        help_text=_('The user to whom this temporary token is associated.')
    )
    token = models.CharField(
        max_length=512,
        unique=True,
        verbose_name=_('Token'),
        help_text=_('A unique token string for temporary access or operations.')
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Created At'),
        help_text=_('The date and time when this token was generated.')
    )
    expires_at = models.DateTimeField(
        verbose_name=_('Expires At'),
        help_text=_('The date and time when this token becomes invalid and cannot be used.')
    )

    def is_valid(self):
        """Check if the token is still valid based on the current time."""
        return timezone.now() < self.expires_at

    def __str__(self):
        return f"Temporary token for {self.user}"