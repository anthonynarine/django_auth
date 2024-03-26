
from django.contrib import admin
from .models import CustomUser, UserToken, Reset
import logging

logger = logging.getLogger(__name__)

@admin.register(CustomUser)
class UserAdmin(admin.ModelAdmin):
    fields = ["first_name", "last_name", "email", "password"]
    list_display = ["first_name", "last_name", "email", "password"]
    
@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    fields = ["user", "token", "last_used_at", "is_revoked"]
    list_display = ["user", "token", "last_used_at", "is_revoked"]