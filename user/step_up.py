"""Reusable step-up assurance policy for sensitive account actions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.utils import timezone
from rest_framework import exceptions, status

from security.models import SecurityEvent
from security.services import record_security_event

AUTH_STRENGTH_ORDER = {
    "password": 1,
    "mfa": 2,
}


@dataclass(frozen=True, slots=True)
class StepUpRequirement:
    minimum_strength: str = "password"
    max_auth_age_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class StepUpEvaluation:
    satisfied: bool
    reason_code: str
    current_strength: str | None
    required_strength: str
    auth_age_seconds: int | None = None
    max_auth_age_seconds: int | None = None


class StepUpRequired(exceptions.APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_code = "step_up_required"
    default_detail = {
        "code": "STEP_UP_REQUIRED",
        "reason": "STEP_UP_REQUIRED",
    }

    def __init__(self, detail=None, code=None):
        super().__init__(detail or self.default_detail, code)


def _normalize_strength(strength: str | None) -> str:
    normalized = (strength or "password").strip().lower()
    return normalized if normalized in AUTH_STRENGTH_ORDER else "password"


def compare_auth_strength(current_strength: str | None, required_strength: str) -> bool:
    current_rank = AUTH_STRENGTH_ORDER.get(_normalize_strength(current_strength), 0)
    required_rank = AUTH_STRENGTH_ORDER.get(_normalize_strength(required_strength), 0)
    return current_rank >= required_rank


def evaluate_step_up(session, requirement: StepUpRequirement) -> StepUpEvaluation:
    required_strength = _normalize_strength(requirement.minimum_strength)

    if session is None:
        return StepUpEvaluation(
            satisfied=False,
            reason_code="AUTH_SESSION_REQUIRED",
            current_strength=None,
            required_strength=required_strength,
            max_auth_age_seconds=requirement.max_auth_age_seconds,
        )

    current_strength = _normalize_strength(getattr(session, "authentication_strength", None))
    if not compare_auth_strength(current_strength, required_strength):
        return StepUpEvaluation(
            satisfied=False,
            reason_code="MFA_REQUIRED" if required_strength == "mfa" else "AUTH_STRENGTH_INSUFFICIENT",
            current_strength=current_strength,
            required_strength=required_strength,
            max_auth_age_seconds=requirement.max_auth_age_seconds,
        )

    recent_auth_at = getattr(session, "recent_auth_at", None)
    if recent_auth_at is None:
        return StepUpEvaluation(
            satisfied=False,
            reason_code="RECENT_AUTH_REQUIRED",
            current_strength=current_strength,
            required_strength=required_strength,
            max_auth_age_seconds=requirement.max_auth_age_seconds,
        )

    max_age_seconds = requirement.max_auth_age_seconds
    if max_age_seconds is not None:
        auth_age = int((timezone.now() - recent_auth_at).total_seconds())
        if auth_age > max_age_seconds:
            return StepUpEvaluation(
                satisfied=False,
                reason_code="RECENT_AUTH_REQUIRED",
                current_strength=current_strength,
                required_strength=required_strength,
                auth_age_seconds=auth_age,
                max_auth_age_seconds=max_age_seconds,
            )
        return StepUpEvaluation(
            satisfied=True,
            reason_code="STEP_UP_SATISFIED",
            current_strength=current_strength,
            required_strength=required_strength,
            auth_age_seconds=auth_age,
            max_auth_age_seconds=max_age_seconds,
        )

    return StepUpEvaluation(
        satisfied=True,
        reason_code="STEP_UP_SATISFIED",
        current_strength=current_strength,
        required_strength=required_strength,
    )


def _step_up_failure_detail(
    evaluation: StepUpEvaluation,
    *,
    operation: str,
):
    detail = {
        "code": "STEP_UP_REQUIRED",
        "reason": evaluation.reason_code,
        "required_strength": evaluation.required_strength,
    }
    if evaluation.current_strength is not None:
        detail["current_strength"] = evaluation.current_strength
    if evaluation.auth_age_seconds is not None:
        detail["auth_age_seconds"] = evaluation.auth_age_seconds
    if evaluation.max_auth_age_seconds is not None:
        detail["max_auth_age_seconds"] = evaluation.max_auth_age_seconds
    if operation:
        detail["operation"] = operation
    return detail


def require_step_up(
    session,
    requirement: StepUpRequirement,
    *,
    request=None,
    user=None,
    operation: str,
    failure_event: str = SecurityEvent.EventType.STEP_UP_REQUIRED,
):
    evaluation = evaluate_step_up(session, requirement)
    if evaluation.satisfied:
        return session

    if evaluation.reason_code == "AUTH_SESSION_REQUIRED":
        raise exceptions.AuthenticationFailed("Active session required.")

    record_security_event(
        failure_event,
        outcome=SecurityEvent.Outcome.DENIED,
        severity=SecurityEvent.Severity.WARNING,
        reason_code=evaluation.reason_code,
        user=user,
        auth_session=session,
        request=request,
        metadata={
            "operation": operation,
            "required_strength": evaluation.required_strength,
            "current_strength": evaluation.current_strength,
            "auth_age_seconds": evaluation.auth_age_seconds,
            "max_auth_age_seconds": evaluation.max_auth_age_seconds,
        },
    )
    raise StepUpRequired(_step_up_failure_detail(evaluation, operation=operation))


STEP_UP_POLICIES = {
    "PASSWORD_CHANGE": StepUpRequirement(minimum_strength="password", max_auth_age_seconds=600),
    "MFA_SETUP": StepUpRequirement(minimum_strength="password", max_auth_age_seconds=600),
    "MFA_DISABLE": StepUpRequirement(minimum_strength="mfa", max_auth_age_seconds=600),
}

