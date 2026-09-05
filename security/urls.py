"""Security audit API routes."""

from django.urls import path

from .views import (
    SecurityControlDetailAPIView,
    SecurityControlListAPIView,
    SecurityDomainListAPIView,
    SecurityEvidenceDetailAPIView,
    SecurityEvidenceListAPIView,
    SecurityEventDetailAPIView,
    SecurityEventListAPIView,
    SecurityFindingDetailAPIView,
    SecurityFindingListAPIView,
    SecurityPostureAPIView,
    SecuritySessionDetailAPIView,
    SecuritySessionListAPIView,
    SecuritySummaryAPIView,
)

app_name = "security"

urlpatterns = [
    path("posture/", SecurityPostureAPIView.as_view(), name="posture"),
    path("domains/", SecurityDomainListAPIView.as_view(), name="domains"),
    path("controls/", SecurityControlListAPIView.as_view(), name="controls"),
    path("controls/<str:control_key>/", SecurityControlDetailAPIView.as_view(), name="control-detail"),
    path("evidence/", SecurityEvidenceListAPIView.as_view(), name="evidence"),
    path("evidence/<uuid:pk>/", SecurityEvidenceDetailAPIView.as_view(), name="evidence-detail"),
    path("events/", SecurityEventListAPIView.as_view(), name="events"),
    path("events/<uuid:pk>/", SecurityEventDetailAPIView.as_view(), name="event-detail"),
    path("findings/", SecurityFindingListAPIView.as_view(), name="findings"),
    path("findings/<uuid:pk>/", SecurityFindingDetailAPIView.as_view(), name="finding-detail"),
    path("summary/", SecuritySummaryAPIView.as_view(), name="summary"),
    path("sessions/", SecuritySessionListAPIView.as_view(), name="sessions"),
    path("sessions/<uuid:pk>/", SecuritySessionDetailAPIView.as_view(), name="session-detail"),
]

