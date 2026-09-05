# Security Controls, Evidence, Findings, and Posture

B-OBS2 adds a durable backend layer for security requirements and security posture. It does not change authentication, authorization, session enforcement, abuse controls, or step-up decisions.

## Architecture

Security enforcement decides whether an action is allowed. `SecurityEvent` records what happened. The B-OBS1 presentation layer translates safe event evidence into human language. B-OBS2 adds `SecurityControl`, `SecurityEvidence`, and `SecurityFinding` so the Observatory can also answer what should be true, how Gait knows, and what currently needs attention.

The Observatory remains read-only for normal API consumers. Presentation and posture logic must never participate in enforcement.

## SecurityControl

`SecurityControl` represents a stable security requirement or invariant. Its semantic identity is `control_key`, not the database UUID. Control keys are unique, stable, machine-readable, and normally immutable after introduction.

Core fields include domain, title, description, control type, lifecycle, status, status reason, failed severity, evaluation timestamps, and review timestamps.

## Domains

Domains are stable enum values with deterministic labels:

- `IDENTITY`
- `SESSION`
- `MFA`
- `ASSURANCE`
- `ABUSE_CONTROL`
- `AUDIT`
- `AUTHORIZATION`
- `DATA_PROTECTION`
- `DATABASE`
- `INFRASTRUCTURE`
- `BACKUP_RECOVERY`
- `INCIDENT_RESPONSE`
- `MONITORING`
- `SECURE_SDLC`
- `VULNERABILITY_MANAGEMENT`
- `GOVERNANCE`
- `VENDOR_RISK`
- `COMPLIANCE_EVIDENCE`
- `AGENT_SECURITY`

Not every domain has controls in B-OBS2. Empty domains are exposed so future backend/frontend work can remain stable.

## Control Types

- `LIVE`: machine evidence may continuously or frequently establish status.
- `PERIODIC`: evidence is expected within a defined interval.
- `DOCUMENTARY`: policy, document, or review evidence establishes status.
- `MANUAL`: human verification is required.

Documentary and manual controls are not treated as live telemetry.

## Control Status

- `HEALTHY`: evidence demonstrates the required condition is satisfied.
- `NEEDS_ATTENTION`: evidence is stale, incomplete, approaching expiration, or requires follow-up.
- `CONTROL_FAILURE`: evidence demonstrates the required condition is not satisfied.
- `UNKNOWN`: there is not enough evidence to determine state.
- `NOT_APPLICABLE`: the control has explicitly been determined not to apply.

No evidence is never treated as healthy. It evaluates to `UNKNOWN` unless a future deterministic rule explicitly proves otherwise.

## Registry Strategy

Controls are defined in `security/control_registry.py` and synchronized into the database after migrations with an idempotent `post_migrate` hook. This keeps control definitions reviewable in code and avoids manual production inserts.

Registry sync creates or updates definition fields only. It does not create evidence and does not mark controls healthy.

## Initial Controls

B-OBS2 registers controls for implemented backend capabilities only:

- `GAIT.AUTH.REFRESH_ROTATION`
- `GAIT.AUTH.REFRESH_REPLAY_PROTECTION`
- `GAIT.SESSION.SERVER_AUTHORITY`
- `GAIT.SESSION.LOGOUT_ALL_REVOCATION`
- `GAIT.MFA.TOTP`
- `GAIT.ASSURANCE.STEP_UP`
- `GAIT.ABUSE.POSTGRES_ENFORCEMENT`
- `GAIT.AUDIT.SECURITY_EVENTS`
- `GAIT.AUDIT.OBSERVATORY_ACCESS`
- `GAIT.ACCOUNT.RESET_ENUMERATION_PROTECTION`
- `GAIT.ACCOUNT.DISABLED_USER_ENFORCEMENT`

Initial status is `UNKNOWN` until trusted evidence exists.

## SecurityEvidence

`SecurityEvidence` is append-oriented evidence supporting a control. It records evidence type, source type/name/reference, title, summary, result, observed time, optional validity window, metadata, and creation time.

Evidence results are distinct from control status:

- `PASS`
- `FAIL`
- `WARNING`
- `INFORMATIONAL`

An evaluator translates evidence into control status.

## Evidence Freshness

If `valid_until` is earlier than the evaluation time, the evidence is stale. A stale latest `PASS` does not keep a control healthy; the generic evaluator marks the control `NEEDS_ATTENTION`.

## Findings

`SecurityFinding` represents a durable security problem requiring investigation, remediation, or explicit disposition. A finding is not the same as a `SecurityEvent`; most events are normal activity and do not create findings.

Finding statuses:

- `OPEN`
- `ACKNOWLEDGED`
- `RESOLVED`
- `ACCEPTED_RISK`
- `FALSE_POSITIVE`

Finding severity reuses `SecurityEvent` severity: `INFO`, `WARNING`, `HIGH`, `CRITICAL`.

Findings include structured fields for expected behavior, observed behavior, affected system/component, source provenance, timestamps, resolution summary, metadata, supporting evidence, and related security events.

## Deduplication

Findings dedupe by unique `finding_key`. Repeated detection updates `last_seen_at`, keeps `first_seen_at`, and attaches new evidence or related events. This prevents unbounded duplicate open findings for the same condition.

Opening or repeating a finding is wrapped in a database transaction and relies on the unique key for race safety.

## Posture Derivation

`GET /api/security/posture/` returns deterministic counts and an overall enum, not a score.

Overall status is derived conservatively:

- any critical active finding or control failure -> `CONTROL_FAILURE`
- any open high/warning finding -> `NEEDS_ATTENTION`
- any control needing attention -> `NEEDS_ATTENTION`
- any unknown applicable control -> `UNKNOWN`
- all applicable controls healthy -> `HEALTHY`

`10 HEALTHY + 1 UNKNOWN` is `UNKNOWN`, not healthy.

## API Contracts

New read-only endpoints:

- `GET /api/security/posture/`
- `GET /api/security/domains/`
- `GET /api/security/controls/`
- `GET /api/security/controls/{control_key}/`
- `GET /api/security/evidence/`
- `GET /api/security/evidence/{id}/`
- `GET /api/security/findings/`
- `GET /api/security/findings/{id}/`

The existing B-OBS1 endpoints are unchanged.

## Privacy

Evidence and finding metadata use the centralized security metadata sanitizer. Obvious secret and PHI-like keys such as passwords, OTPs, JWTs, refresh tokens, authorization headers, MFA secrets, private keys, API keys, patient identifiers, diagnosis, and PHI are redacted.

Descriptions should use safe identifiers such as component names, endpoint names, principal IDs, session IDs, event IDs, and tenant/resource identifiers. Do not store raw clinical content.

## Future Integrations

B-OBS2 defines durable contracts only. B-OBS3 may add ingestion from CI, GitHub, vulnerability tools, backup systems, cloud checks, or manual review workflows.

## Master Remediation Agent Contract

A future remediation agent may consume:

- `SecurityFinding`
- linked `SecurityControl`
- linked `SecurityEvidence`
- related `SecurityEvent` records

That data is intended to support precise coding-agent repair prompts. The remediation agent will not automatically modify production.
