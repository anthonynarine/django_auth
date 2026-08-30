"""Permissions for the security audit API."""

from rest_framework.permissions import BasePermission


class CanViewSecurityAudit(BasePermission):
    """Restrict audit access to staff users for now."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)

