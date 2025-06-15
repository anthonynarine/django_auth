# user/constants.py

from django.utils.translation import gettext_lazy as _
from django.db import models

class RoleChoices(models.TextChoices):
    ADMIN = "admin", _("Admin")
    PHYSICIAN = "physician", _("Physician")
    TECHNOLOGIST = "technologist", _("Technologist")
