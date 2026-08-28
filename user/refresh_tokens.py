# Filename: user/refresh_tokens.py
"""Refresh-token lifecycle services for A1 hardening."""

from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from django.conf import settings
from django.db import transaction
from django.utils import timezone as django_timezone
from rest_framework import exceptions

from .auth_token import JWT_REFRESH_SECRET, create_access_token, create_refresh_token
from .models import UserToken

logger = logging.getLogger(__name__)

REFRESH_TOKEN_DAYS = 7


class InvalidRefreshToken(exceptions.AuthenticationFailed):
    default_detail = "Invalid refresh token."


class ExpiredRefreshToken(exceptions.AuthenticationFailed):
    default_detail = "The token has expired."


class RevokedRefreshToken(exceptions.AuthenticationFailed):
    default_detail = "unauthenticated"


class RefreshReplayDetected(exceptions.AuthenticationFailed):
    default_detail = "unauthenticated"


@dataclass(frozen=True)
class IssuedRefreshToken:
    token: str
    record: UserToken


@dataclass(frozen=True)
class RotatedRefreshToken:
    access_token: str
    refresh_token: str
    old_record: UserToken
    new_record: UserToken


def get_client_ip(request) -> str | None:
    """Return a best-effort client IP for non-secret token metadata."""
    if request is None:
        return None
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or None
    return request.META.get("REMOTE_ADDR")


def hash_refresh_token(token: str) -> str:
    """Create a deterministic keyed digest for high-entropy refresh tokens."""
    return hmac.new(
        settings.JWT_REFRESH_SECRET.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_refresh_token_payload(user, *, jti: uuid.UUID, family_id: uuid.UUID) -> dict:
    """Build the refresh JWT payload for new hardened tokens."""
    now = datetime.now(timezone.utc)
    return {
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "type": "refresh",
        "jti": str(jti),
        "family_id": str(family_id),
        "exp": now + timedelta(days=REFRESH_TOKEN_DAYS),
        "iat": now,
    }


def issue_refresh_token(
    user,
    *,
    family_id: uuid.UUID | None = None,
    request=None,
) -> IssuedRefreshToken:
    """Issue a new hashed refresh token and persist its server-side state."""
    if not settings.JWT_REFRESH_ROTATION_ENABLED:
        token = create_refresh_token(user.id)
        record = UserToken.objects.create(
            user=user,
            token=token,
            expired_at=django_timezone.now() + timedelta(days=REFRESH_TOKEN_DAYS),
            created_ip=get_client_ip(request),
            last_used_ip=get_client_ip(request),
            user_agent=(request.META.get("HTTP_USER_AGENT", "")[:2048] if request else ""),
        )
        return IssuedRefreshToken(token=token, record=record)

    family_id = family_id or uuid.uuid4()
    jti = uuid.uuid4()
    payload = create_refresh_token_payload(user, jti=jti, family_id=family_id)
    token = jwt.encode(payload, JWT_REFRESH_SECRET, algorithm="HS256")
    record = UserToken.objects.create(
        user=user,
        token=None,
        token_hash=hash_refresh_token(token),
        jti=jti,
        family_id=family_id,
        expired_at=django_timezone.now() + timedelta(days=REFRESH_TOKEN_DAYS),
        created_ip=get_client_ip(request),
        last_used_ip=get_client_ip(request),
        user_agent=(request.META.get("HTTP_USER_AGENT", "")[:2048] if request else ""),
    )
    return IssuedRefreshToken(token=token, record=record)


def decode_refresh_payload(token: str) -> dict:
    """Decode a refresh token JWT without exposing the raw credential."""
    try:
        return jwt.decode(token, JWT_REFRESH_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise ExpiredRefreshToken("The token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        logger.warning("Invalid refresh token presented: %s", exc)
        raise InvalidRefreshToken("Invalid token.") from exc


def _lookup_refresh_record(payload: dict, token: str) -> UserToken:
    token_hash = hash_refresh_token(token)
    jti = payload.get("jti")

    queryset = UserToken.objects.select_for_update()
    if jti:
        record = queryset.filter(jti=jti).first()
        if record:
            return record

    record = queryset.filter(token_hash=token_hash).first()
    if record:
        return record

    # Legacy compatibility: production rows before A1 stored raw refresh tokens.
    record = queryset.filter(token=token).first()
    if record:
        return record

    raise InvalidRefreshToken("unauthenticated")


def revoke_refresh_family(family_id, *, reason: str) -> int:
    """Revoke every token in one refresh-token family."""
    if not family_id:
        return 0
    now = django_timezone.now()
    return UserToken.objects.filter(family_id=family_id, revoked_at__isnull=True).update(
        is_revoked=True,
        revoked_at=now,
        revocation_reason=reason,
    )


def _ensure_record_can_rotate(record: UserToken, payload: dict) -> None:
    now = django_timezone.now()
    if record.expired_at <= now:
        raise ExpiredRefreshToken("The token has expired.")

    if record.revoked_at is not None or record.is_revoked:
        raise RevokedRefreshToken("unauthenticated")

    if record.family_id and UserToken.objects.filter(
        family_id=record.family_id,
        revoked_at__isnull=False,
    ).exists():
        raise RevokedRefreshToken("unauthenticated")

    payload_jti = payload.get("jti")
    if record.jti and payload_jti and str(record.jti) != str(payload_jti):
        raise InvalidRefreshToken("unauthenticated")

    if int(payload.get("user_id")) != record.user_id:
        raise InvalidRefreshToken("unauthenticated")


def rotate_refresh_token(token: str, *, request=None) -> RotatedRefreshToken:
    """Atomically consume one refresh token and issue its replacement."""
    if not settings.JWT_REFRESH_ROTATION_ENABLED:
        return refresh_without_rotation(token, request=request)

    payload = decode_refresh_payload(token)
    if payload.get("type") not in (None, "refresh"):
        raise InvalidRefreshToken("Invalid token.")

    replay_detected = False
    with transaction.atomic():
        record = _lookup_refresh_record(payload, token)
        if record.consumed_at is not None:
            revoke_refresh_family(record.family_id, reason="REPLAY_DETECTED")
            replay_detected = True
        else:
            _ensure_record_can_rotate(record, payload)

            family_id = record.family_id
            if not family_id:
                family_id = uuid.UUID(payload["family_id"]) if payload.get("family_id") else uuid.uuid4()
            if not record.family_id:
                record.family_id = family_id
            if not record.jti:
                record.jti = uuid.UUID(payload["jti"]) if payload.get("jti") else uuid.uuid4()
            if not record.token_hash:
                record.token_hash = hash_refresh_token(token)

            issued = issue_refresh_token(record.user, family_id=family_id, request=request)
            now = django_timezone.now()
            record.consumed_at = now
            record.replaced_by_jti = issued.record.jti
            record.last_used_at = now
            record.last_used_ip = get_client_ip(request)
            record.save(
                update_fields=[
                    "family_id",
                    "jti",
                    "token_hash",
                    "consumed_at",
                    "replaced_by_jti",
                    "last_used_at",
                    "last_used_ip",
                ]
            )

    if replay_detected:
        raise RefreshReplayDetected("unauthenticated")

    access_token = create_access_token(record.user_id)
    return RotatedRefreshToken(
        access_token=access_token,
        refresh_token=issued.token,
        old_record=record,
        new_record=issued.record,
    )


def refresh_without_rotation(token: str, *, request=None) -> RotatedRefreshToken:
    """Compatibility fallback for production rollback via feature flag."""
    payload = decode_refresh_payload(token)
    with transaction.atomic():
        record = _lookup_refresh_record(payload, token)
        now = django_timezone.now()
        if record.expired_at <= now:
            raise ExpiredRefreshToken("The token has expired.")
        if record.revoked_at is not None or record.is_revoked:
            raise RevokedRefreshToken("unauthenticated")
        record.last_used_ip = get_client_ip(request)
        record.save(update_fields=["last_used_ip", "last_used_at"])

    access_token = create_access_token(record.user_id)
    return RotatedRefreshToken(
        access_token=access_token,
        refresh_token=token,
        old_record=record,
        new_record=record,
    )


def revoke_refresh_token(token: str, *, reason: str = "LOGOUT") -> bool:
    """Revoke the family for an identifiable refresh token."""
    try:
        payload = decode_refresh_payload(token)
    except exceptions.AuthenticationFailed:
        payload = {}

    with transaction.atomic():
        try:
            record = _lookup_refresh_record(payload, token)
        except exceptions.AuthenticationFailed:
            return False

        if not record.family_id:
            record.family_id = (
                uuid.UUID(payload["family_id"]) if payload.get("family_id") else uuid.uuid4()
            )
            if not record.jti:
                record.jti = uuid.UUID(payload["jti"]) if payload.get("jti") else uuid.uuid4()
            if not record.token_hash:
                record.token_hash = hash_refresh_token(token)
            record.save(update_fields=["family_id", "jti", "token_hash"])

        revoke_refresh_family(record.family_id, reason=reason)
        return True
