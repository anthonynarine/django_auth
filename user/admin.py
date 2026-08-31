
from django.contrib import admin
from .models import CustomUser, UserToken, Reset
from .account_security_services import mark_account_disabled
import logging

logger = logging.getLogger(__name__)

@admin.register(CustomUser)
class UserAdmin(admin.ModelAdmin):
    fields = [
        "first_name",
        "last_name",
        "email",
        "is_staff",
        "is_superuser",
        "is_active",
        "is_2fa_enabled",
    ]
    list_display = [
        "first_name",
        "last_name",
        "email",
        "is_staff",
        "is_superuser",
        "is_active",
        "is_2fa_enabled",
    ]

    def save_model(self, request, obj, form, change):
        was_active = None
        if obj.pk:
            was_active = (
                CustomUser.objects.filter(pk=obj.pk)
                .values_list("is_active", flat=True)
                .first()
            )
        super().save_model(request, obj, form, change)
        if was_active and not obj.is_active:
            mark_account_disabled(user=obj, request=request)
    
@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    fields = ["user", "last_used_at", "is_revoked"]
    list_display = ["user", "last_used_at", "is_revoked"]
