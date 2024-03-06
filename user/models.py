
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _


class CustomUser(AbstractUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(_("email address"), unique=True)
    password = models.CharField(max_length=255)
    username = None
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    