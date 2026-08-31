from django.db import models


class AbuseCounter(models.Model):
    scope = models.CharField(max_length=64)
    key_hash = models.CharField(max_length=64)
    window_started_at = models.DateTimeField()
    window_expires_at = models.DateTimeField(db_index=True)
    attempt_count = models.PositiveIntegerField(default=0)
    blocked_until = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["scope", "key_hash"], name="abuse_scope_key_uniq"),
        ]
        indexes = [
            models.Index(fields=["scope", "window_expires_at"], name="abuse_scope_window_idx"),
            models.Index(fields=["scope", "blocked_until"], name="abuse_scope_block_idx"),
        ]
        ordering = ["scope", "key_hash"]

    def __str__(self):
        return f"{self.scope}:{self.key_hash[:12]}"
