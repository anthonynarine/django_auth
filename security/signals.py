"""Security app lifecycle hooks."""

from django.db.models.signals import post_migrate
from django.dispatch import receiver


@receiver(post_migrate)
def sync_security_controls_after_migrate(sender, **kwargs):
    if sender.name != "security":
        return
    from security.services import sync_security_control_registry

    sync_security_control_registry()
