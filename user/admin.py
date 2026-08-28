
from django.contrib import admin
from .models import CustomUser, UserToken, Reset
import logging

logger = logging.getLogger(__name__)

@admin.register(CustomUser)
class UserAdmin(admin.ModelAdmin):
    fields = ["first_name", "last_name", "email", "is_2fa_enabled"]
    list_display = ["first_name", "last_name", "email", "is_2fa_enabled" ]
    
@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    fields = ["user", "last_used_at", "is_revoked"]
    list_display = ["user", "last_used_at", "is_revoked"]
