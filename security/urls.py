"""Security audit API routes."""

from django.urls import path

from .views import (
    SecurityEventDetailAPIView,
    SecurityEventListAPIView,
    SecuritySessionDetailAPIView,
    SecuritySessionListAPIView,
    SecuritySummaryAPIView,
)

app_name = "security"

urlpatterns = [
    path("events/", SecurityEventListAPIView.as_view(), name="events"),
    path("events/<uuid:pk>/", SecurityEventDetailAPIView.as_view(), name="event-detail"),
    path("summary/", SecuritySummaryAPIView.as_view(), name="summary"),
    path("sessions/", SecuritySessionListAPIView.as_view(), name="sessions"),
    path("sessions/<uuid:pk>/", SecuritySessionDetailAPIView.as_view(), name="session-detail"),
]

