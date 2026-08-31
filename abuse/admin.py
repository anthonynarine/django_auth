from django.contrib import admin

from .models import AbuseCounter


@admin.register(AbuseCounter)
class AbuseCounterAdmin(admin.ModelAdmin):
    list_display = ["scope", "attempt_count", "window_started_at", "window_expires_at", "blocked_until", "updated_at"]
    list_filter = ["scope", "blocked_until"]
    search_fields = ["scope", "key_hash"]
    readonly_fields = [field.name for field in AbuseCounter._meta.fields]
