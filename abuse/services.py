from __future__ import annotations

import hmac
import json
import logging
from dataclasses import dataclass
from hashlib import sha256
from datetime import timedelta
from typing import Any, Iterable

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from security.models import SecurityEvent
from security.services import record_security_event
from security.utils import get_client_ip

from .models import AbuseCounter

logger = logging.getLogger(__name__)


class AbuseState:
    NORMAL = "NORMAL"
    THROTTLED = "THROTTLED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class AbuseDecision:
    allowed: bool
    state: str
    scope: str
    retry_after_seconds: int | None
    attempt_count: int


def _enforcement_mode() -> str:
    return getattr(settings, "ABUSE_CONTROL_ENFORCEMENT", "ENFORCE").upper()


def _policy(scope: str) -> dict[str, int]:
    try:
        return settings.ABUSE_CONTROL_POLICIES[scope]
    except KeyError as exc:
        raise KeyError(f"Unknown abuse control scope: {scope}") from exc


def _normalize_scalar(value: Any) -> str:
    if value is None:
        return ""
    if hasattr(value, "hex") and callable(getattr(value, "hex", None)):
        try:
            return str(value)
        except Exception:
            pass
    return str(value).strip().lower()


def _build_key_material(*, request=None, user=None, auth_session=None, account: str | None = None) -> dict[str, str]:
    material: dict[str, str] = {}
    client_ip = get_client_ip(request)
    if client_ip:
        material["ip"] = client_ip
    if account:
        material["account"] = _normalize_scalar(account)
    if user is not None and getattr(user, "id", None) is not None:
        material["user_id"] = str(user.id)
    if auth_session is not None and getattr(auth_session, "id", None) is not None:
        material["session_id"] = str(auth_session.id)
    return material


def build_context(*, request=None, user=None, auth_session=None, account: str | None = None) -> dict[str, str]:
    return _build_key_material(request=request, user=user, auth_session=auth_session, account=account)


def _key_hash(scope: str, context: dict[str, str]) -> str:
    payload = {
        "scope": scope,
        "context": {key: context[key] for key in sorted(context)},
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        raw.encode("utf-8"),
        sha256,
    )
    return digest.hexdigest()


def _counter_state(counter: AbuseCounter, now, policy: dict[str, int]) -> str:
    if counter.blocked_until and counter.blocked_until > now:
        return AbuseState.BLOCKED
    if counter.attempt_count >= policy["block_threshold"]:
        return AbuseState.BLOCKED
    if counter.attempt_count >= policy["throttle_threshold"]:
        return AbuseState.THROTTLED
    return AbuseState.NORMAL


def _retry_after_seconds(counter: AbuseCounter, now, policy: dict[str, int], state: str) -> int | None:
    if state == AbuseState.BLOCKED and counter.blocked_until:
        remaining = int((counter.blocked_until - now).total_seconds())
        return max(1, remaining)
    if state == AbuseState.THROTTLED:
        remaining = int((counter.window_expires_at - now).total_seconds())
        return max(1, remaining)
    return None


def _scope_event_type(scope: str, state: str) -> str:
    family = scope.split("_", 1)[0]
    mapping = {
        ("LOGIN", AbuseState.THROTTLED): SecurityEvent.EventType.LOGIN_THROTTLED,
        ("LOGIN", AbuseState.BLOCKED): SecurityEvent.EventType.LOGIN_BLOCKED,
        ("OTP", AbuseState.THROTTLED): SecurityEvent.EventType.OTP_THROTTLED,
        ("OTP", AbuseState.BLOCKED): SecurityEvent.EventType.OTP_BLOCKED,
        ("PASSWORD_RESET", AbuseState.THROTTLED): SecurityEvent.EventType.PASSWORD_RESET_THROTTLED,
        ("PASSWORD_RESET", AbuseState.BLOCKED): SecurityEvent.EventType.PASSWORD_RESET_BLOCKED,
        ("PASSWORD_CHANGE", AbuseState.THROTTLED): SecurityEvent.EventType.PASSWORD_CHANGE_THROTTLED,
        ("PASSWORD_CHANGE", AbuseState.BLOCKED): SecurityEvent.EventType.PASSWORD_CHANGE_BLOCKED,
        ("REAUTH", AbuseState.THROTTLED): SecurityEvent.EventType.REAUTH_THROTTLED,
        ("REAUTH", AbuseState.BLOCKED): SecurityEvent.EventType.REAUTH_BLOCKED,
        ("MFA_CHANGE", AbuseState.THROTTLED): SecurityEvent.EventType.MFA_CHANGE_THROTTLED,
        ("MFA_CHANGE", AbuseState.BLOCKED): SecurityEvent.EventType.MFA_CHANGE_BLOCKED,
    }
    return mapping.get((family, state), "")


def _scope_reason_code(scope: str, state: str) -> str:
    if state == AbuseState.BLOCKED:
        return "TEMPORARY_BLOCK"
    return "RATE_LIMIT_EXCEEDED"


def _record_transition_event(*, scope: str, state: str, request=None, user=None, auth_session=None, attempts: int, retry_after: int | None):
    event_type = _scope_event_type(scope, state)
    if not event_type:
        return
    record_security_event(
        event_type,
        outcome=SecurityEvent.Outcome.DENIED,
        severity=SecurityEvent.Severity.HIGH if state == AbuseState.BLOCKED else SecurityEvent.Severity.WARNING,
        reason_code=_scope_reason_code(scope, state),
        user=user,
        auth_session=auth_session,
        request=request,
        metadata={
            "scope": scope,
            "state": state,
            "attempt_count": attempts,
            "retry_after_seconds": retry_after,
        },
    )


def _locked_counter(scope: str, key_hash: str, policy: dict[str, int]) -> tuple[AbuseCounter | None, bool]:
    try:
        counter = AbuseCounter.objects.select_for_update().get(scope=scope, key_hash=key_hash)
        return counter, False
    except AbuseCounter.DoesNotExist:
        return None, False


def _create_or_lock_counter(scope: str, key_hash: str, now, policy: dict[str, int]) -> AbuseCounter:
    while True:
        try:
            counter, created = AbuseCounter.objects.select_for_update().get_or_create(
                scope=scope,
                key_hash=key_hash,
                defaults={
                    "window_started_at": now,
                    "window_expires_at": now + timedelta(seconds=policy["window_seconds"]),
                    "attempt_count": 0,
                },
            )
            if created:
                return counter
            return counter
        except IntegrityError:
            continue


def _reset_if_expired(counter: AbuseCounter, now, policy: dict[str, int]) -> bool:
    if counter.window_expires_at > now:
        return False
    counter.window_started_at = now
    counter.window_expires_at = now + timedelta(seconds=policy["window_seconds"])
    counter.attempt_count = 0
    counter.blocked_until = None
    return True


def _decision(scope: str, counter: AbuseCounter, now, policy: dict[str, int], *, allowed: bool) -> AbuseDecision:
    state = _counter_state(counter, now, policy)
    return AbuseDecision(
        allowed=allowed,
        state=state,
        scope=scope,
        retry_after_seconds=_retry_after_seconds(counter, now, policy, state),
        attempt_count=counter.attempt_count,
    )


def check(scope: str, *, request=None, user=None, auth_session=None, account: str | None = None) -> AbuseDecision:
    if _enforcement_mode() == "OFF":
        return AbuseDecision(True, AbuseState.NORMAL, scope, None, 0)

    context = build_context(request=request, user=user, auth_session=auth_session, account=account)
    if not context:
        return AbuseDecision(True, AbuseState.NORMAL, scope, None, 0)

    policy = _policy(scope)
    now = timezone.now()
    key_hash = _key_hash(scope, context)
    with transaction.atomic():
        counter = AbuseCounter.objects.filter(scope=scope, key_hash=key_hash).first()
        if counter is None:
            return AbuseDecision(True, AbuseState.NORMAL, scope, None, 0)
        counter = AbuseCounter.objects.select_for_update().get(pk=counter.pk)
        _reset_if_expired(counter, now, policy)
        state_before = _counter_state(counter, now, policy)
        if state_before == AbuseState.NORMAL:
            return _decision(scope, counter, now, policy, allowed=True)

        counter.attempt_count += 1
        if counter.attempt_count >= policy["block_threshold"]:
            counter.blocked_until = now + timedelta(seconds=policy["block_seconds"])
        counter.save(update_fields=["attempt_count", "blocked_until", "window_started_at", "window_expires_at", "updated_at"])
        state_after = _counter_state(counter, now, policy)
        if state_after != state_before:
            _record_transition_event(
                scope=scope,
                state=state_after,
                request=request,
                user=user,
                auth_session=auth_session,
                attempts=counter.attempt_count,
                retry_after=_retry_after_seconds(counter, now, policy, state_after),
            )
        return _decision(scope, counter, now, policy, allowed=False)


def record_failure(scope: str, *, request=None, user=None, auth_session=None, account: str | None = None) -> AbuseDecision:
    if _enforcement_mode() == "OFF":
        return AbuseDecision(True, AbuseState.NORMAL, scope, None, 0)

    context = build_context(request=request, user=user, auth_session=auth_session, account=account)
    policy = _policy(scope)
    now = timezone.now()
    key_hash = _key_hash(scope, context)
    with transaction.atomic():
        counter = _create_or_lock_counter(scope, key_hash, now, policy)
        _reset_if_expired(counter, now, policy)
        state_before = _counter_state(counter, now, policy)
        counter.attempt_count += 1
        if counter.attempt_count >= policy["block_threshold"]:
            counter.blocked_until = now + timedelta(seconds=policy["block_seconds"])
        counter.save(update_fields=["attempt_count", "blocked_until", "window_started_at", "window_expires_at", "updated_at"])
        state_after = _counter_state(counter, now, policy)
        if state_after != state_before and state_after != AbuseState.NORMAL:
            _record_transition_event(
                scope=scope,
                state=state_after,
                request=request,
                user=user,
                auth_session=auth_session,
                attempts=counter.attempt_count,
                retry_after=_retry_after_seconds(counter, now, policy, state_after),
            )
        return _decision(scope, counter, now, policy, allowed=state_after == AbuseState.NORMAL)


def record_success(
    scope: str | Iterable[str],
    *,
    request=None,
    user=None,
    auth_session=None,
    account: str | None = None,
) -> None:
    if _enforcement_mode() == "OFF":
        return

    scopes = [scope] if isinstance(scope, str) else list(scope)
    if not scopes:
        return

    context = build_context(request=request, user=user, auth_session=auth_session, account=account)
    now = timezone.now()
    with transaction.atomic():
        for one_scope in scopes:
            policy = _policy(one_scope)
            key_hash = _key_hash(one_scope, context)
            counter = AbuseCounter.objects.filter(scope=one_scope, key_hash=key_hash).select_for_update().first()
            if counter is None:
                continue
            counter.window_started_at = now
            counter.window_expires_at = now + timedelta(seconds=policy["window_seconds"])
            counter.attempt_count = 0
            counter.blocked_until = None
            counter.save(update_fields=["window_started_at", "window_expires_at", "attempt_count", "blocked_until", "updated_at"])
