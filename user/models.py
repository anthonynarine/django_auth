# Standard library imports
import uuid
from enum import unique


# Third-party imports
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.forms import DateTimeField
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from user.roles import RoleChoices

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
    is_2fa_setup_in_progress = models.BooleanField(
        default=False,
        verbose_name="Is 2FA Setup in Progress",
        help_text="Tracks whether the 2Fa setup process is ongoing"
    )
    role = models.CharField(
        max_length=20,
        choices=RoleChoices.choices,
        default=RoleChoices.TECHNOLOGIST,
        help_text="User's role in the system (admin, physician, technologist)."
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email


class AuthSession(models.Model):
    """Server-controlled authenticated session for a user."""

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="Session ID",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="auth_sessions",
        verbose_name="User",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Created At",
    )
    last_seen_at = models.DateTimeField(
        default=timezone.now,
        verbose_name="Last Seen At",
    )
    expires_at = models.DateTimeField(
        verbose_name="Expires At",
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Revoked At",
    )
    revocation_reason = models.CharField(
        max_length=64,
        blank=True,
        default="",
        verbose_name="Revocation Reason",
    )
    authentication_method = models.CharField(
        max_length=32,
        default="password",
        verbose_name="Authentication Method",
    )
    authentication_strength = models.CharField(
        max_length=32,
        default="password",
        verbose_name="Authentication Strength",
    )
    recent_auth_at = models.DateTimeField(
        default=timezone.now,
        verbose_name="Recent Auth At",
    )
    created_ip = models.GenericIPAddressField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["user", "revoked_at"], name="user_authses_user_revoked_idx"),
            models.Index(fields=["expires_at"], name="user_authses_expires_idx"),
        ]

    def __str__(self):
        return f"AuthSession({self.id}) for {self.user}"

class UserToken(models.Model):
    """
    Model for storing refresh tokens for users.
    
    Attributes:
        user (ForeignKey): Reference to the user who owns this token.
        token (CharField): The actual token string, which must be unique.
        created_at (DateTimeField): The date and time when this token was created.
        expired_at (DateTimeField): The date and time when this token will expire.
        is_revoked (BooleanField): Indicates whether this token has been revoked.
        last_used_at (DateTimeField): The last date and time this token was used
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        verbose_name='User',
        help_text='The user who owns this token.'
    )
    auth_session = models.ForeignKey(
        "AuthSession",
        on_delete=models.CASCADE,
        related_name="refresh_tokens",
        null=True,
        blank=True,
        verbose_name="Auth Session",
        help_text="Server-controlled session that owns this refresh token.",
    )
    token = models.CharField(
        max_length=512,
        unique=True,
        null=True,
        blank=True,
        verbose_name='Token',
        help_text='Legacy raw token string. New refresh tokens store only a hash.'
    )
    token_hash = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        verbose_name='Token Hash',
        help_text='HMAC-SHA256 digest used to look up hardened refresh tokens.'
    )
    jti = models.UUIDField(
        unique=True,
        null=True,
        blank=True,
        verbose_name='JWT ID',
        help_text='Unique identifier embedded in hardened refresh JWTs.'
    )
    family_id = models.UUIDField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name='Token Family ID',
        help_text='Identifier shared by rotated refresh tokens from one login.'
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
    consumed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Consumed At',
        help_text='When this refresh token was rotated and made single-use.'
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Revoked At',
        help_text='When this refresh token was explicitly revoked.'
    )
    revocation_reason = models.CharField(
        max_length=64,
        blank=True,
        default='',
        verbose_name='Revocation Reason'
    )
    replaced_by_jti = models.UUIDField(
        null=True,
        blank=True,
        verbose_name='Replacement JWT ID',
        help_text='JTI of the refresh token issued when this token was consumed.'
    )
    created_ip = models.GenericIPAddressField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default='')
    last_used_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Last Used At',
        help_text='The last date and time this token was used.'
    )

    class Meta:
        indexes = [
            models.Index(
                fields=["family_id", "revoked_at"],
                name="user_userto_family_6cc020_idx",
            ),
            models.Index(
                fields=["user", "family_id"],
                name="user_userto_user_id_2217ff_idx",
            ),
            models.Index(
                fields=["auth_session", "revoked_at"],
                name="user_userto_sess_revoked_idx",
            ),
        ]

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
