# Live Security Events

## Purpose

The Live Security Observatory explains current Gait security activity to staff operators without changing the underlying security evidence. It is focused on live authentication, session, MFA, account-security, step-up, and abuse-control events already emitted by the backend.

It is not a compliance, posture, vulnerability, backup, CI, or readiness system.

## Architecture

The security layers stay separate:

1. Enforcement decides whether an action is allowed.
2. Audit records what happened as a canonical `SecurityEvent`.
3. Presentation translates safe evidence into deterministic human language.
4. Observatory exposes the technical evidence and human explanation to authorized staff clients.

Presentation logic never participates in authentication, authorization, revocation, throttling, or any other enforcement decision.

## Canonical Evidence

`SecurityEvent` is the durable audit record. Its canonical fields remain authoritative:

- `event_type`
- `outcome`
- `severity`
- `reason_code`
- `user`
- `auth_session`
- request context
- sanitized `metadata`

These values are machine-readable evidence. They should not be renamed or repurposed for display copy.

## Presentation Layer

`security.presentation.describe_security_event(event)` maps an already-sanitized `SecurityEvent` to deterministic human fields:

- `title`
- `description`
- `category`
- `category_label`
- `severity_label`
- `system_response`
- `impact_summary`
- `recommended_action`

The mapping is static Python code. It does not call an LLM, perform database queries, inspect raw credentials, or infer facts that are not supported by the event semantics.

## Event Categories

Current categories are limited to existing event families:

- `AUTHENTICATION` -> Authentication
- `SESSION_SECURITY` -> Session security
- `MFA` -> Multi-factor authentication
- `ACCOUNT_SECURITY` -> Account security
- `ABUSE_CONTROL` -> Abuse control
- `STEP_UP` -> Step-up verification
- `SYSTEM_SECURITY` -> System security

Do not add future-facing categories until a real event family needs them.

## Human Severity Mapping

Canonical severity values are preserved. The human labels are:

- `INFO` -> Normal activity
- `WARNING` -> Needs attention
- `HIGH` -> Security concern
- `CRITICAL` -> Immediate attention

No numeric score is produced by this milestone.

## Reason-Code Handling

The presentation layer may specialize a small number of meaningful `reason_code` values. Examples include:

- `STEP_UP_REQUIRED` + `RECENT_AUTH_REQUIRED`
- `STEP_UP_REQUIRED` + `MFA_REQUIRED`
- `STEP_UP_REQUIRED` + `AUTH_STRENGTH_INSUFFICIENT`
- `STEP_UP_FAILURE` + `INVALID_PASSWORD`
- `STEP_UP_FAILURE` + `INVALID_OTP`

Unknown reason codes degrade to the event-type explanation.

## Fallback Behavior

If a new `event_type` is recorded before presentation copy is added, serialization must not crash. The fallback is:

- title: Security activity recorded
- description: Gait recorded a security-related event.
- category: `SYSTEM_SECURITY`
- recommended action: Review technical details for more information.

The original `event_type` remains visible in the API payload.

## Privacy Rules

The Observatory must never expose or persist raw secrets such as passwords, OTP values, MFA secrets, JWTs, refresh tokens, Authorization headers, database credentials, private keys, CSRF secrets, or API keys.

`record_security_event()` uses `sanitize_security_metadata()` before persistence. Presentation code reads only the stored event object and must treat `metadata` as already sanitized. It must not construct human descriptions from raw credential data or clinical/PHI content.

Allowed evidence for presentation includes event IDs, principal IDs, session IDs, safe resource identifiers, operation names, reason codes, outcomes, severities, and sanitized metadata.

## API Additions

`GET /api/security/events/` and `GET /api/security/events/{id}/` include the human presentation fields listed above in addition to existing canonical fields.

`GET /api/security/sessions/` and `GET /api/security/sessions/{id}/` include `status_description` for the existing session state:

- Active
- Revoked
- Expired

`GET /api/security/summary/` remains a live activity summary and includes stable category and severity label maps for clients.

## Extension Procedure

When adding a future security event:

1. Add the canonical event type to `SecurityEvent.EventType`.
2. Emit the event from the enforcement or service layer that owns the decision.
3. Include only safe metadata; verify secret-looking values are redacted.
4. Add deterministic presentation mapping in `security.presentation`.
5. Add tests for title, category, human severity, description, response, impact, recommendation, and any reason-code specialization.
6. Verify unknown-event fallback remains safe.
7. Run Django checks, migration drift checks, and the relevant security regression suite.

After that, the Observatory API can render the event without frontend-specific backend logic.
