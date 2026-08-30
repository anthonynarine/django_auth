"""Read-only security audit API."""

from __future__ import annotations

from datetime import timedelta

from django.utils import dateparse, timezone
from rest_framework import generics
from rest_framework.response import Response

from user.auth_token import JWTAuthentication

from .pagination import SecurityEventPagination, SecuritySessionPagination
from .permissions import CanViewSecurityAudit
from .selectors import get_security_summary, list_security_events, list_security_sessions
from .serializers import AuthSessionSerializer, SecurityEventSerializer
from security.models import SecurityEvent


def _parse_datetime(value):
    if not value:
        return None
    parsed = dateparse.parse_datetime(value)
    if parsed and timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


class SecurityEventListAPIView(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [CanViewSecurityAudit]
    serializer_class = SecurityEventSerializer
    pagination_class = SecurityEventPagination

    def get_queryset(self):
        params = self.request.query_params
        return list_security_events(
            event_type=params.get("event_type"),
            outcome=params.get("outcome"),
            severity=params.get("severity"),
            user=params.get("user"),
            session=params.get("session"),
            created_from=_parse_datetime(params.get("created_from")),
            created_to=_parse_datetime(params.get("created_to")),
        )


class SecurityEventDetailAPIView(generics.RetrieveAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [CanViewSecurityAudit]
    serializer_class = SecurityEventSerializer
    queryset = SecurityEvent.objects.select_related("user", "auth_session")


class SecuritySummaryAPIView(generics.GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [CanViewSecurityAudit]

    def get(self, request, *args, **kwargs):
        window = timedelta(hours=int(request.query_params.get("window_hours", 24)))
        return Response(get_security_summary(window=window))


class SecuritySessionListAPIView(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [CanViewSecurityAudit]
    serializer_class = AuthSessionSerializer
    pagination_class = SecuritySessionPagination

    def get_queryset(self):
        params = self.request.query_params
        active = params.get("active")
        revoked = params.get("revoked")
        return list_security_sessions(
            user=params.get("user"),
            active=None if active is None else active.lower() == "true",
            revoked=None if revoked is None else revoked.lower() == "true",
            created_from=_parse_datetime(params.get("created_from")),
            created_to=_parse_datetime(params.get("created_to")),
        ).order_by("-created_at", "-id")


class SecuritySessionDetailAPIView(generics.RetrieveAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [CanViewSecurityAudit]
    serializer_class = AuthSessionSerializer
    queryset = list_security_sessions().order_by("-created_at", "-id")
