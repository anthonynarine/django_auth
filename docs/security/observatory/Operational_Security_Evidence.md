# Operational Security Evidence

This document describes the B-OBS3 evidence layer that turns trusted
verification results into deterministic `SecurityEvidence` records.

## Architecture

- `SecurityEvent` records what happened inside the enforcement layer.
- Evidence producers verify a condition outside the enforcement flow.
- `SecurityEvidence` stores the sanitized verification result.
- `SecurityControl` evaluates from trusted evidence only.
- `SecurityFinding` records durable failures that need attention.
- The Security Observatory renders the resulting state.

Presentation and evaluation are deterministic. There is no LLM step and no
automatic health inference from feature presence.

## Trust Boundary

Only trusted internal producers may create operational evidence:

- CI automation that runs the auth/security workflow
- runtime configuration checks

The public Observatory API remains read-only. A caller cannot submit arbitrary
`PASS` evidence through the staff read endpoints.

## Producer Authentication

The current implementation uses trusted Django management commands:

- `manage.py security_collect_evidence`
- `manage.py security_check_configuration`

These commands are intended to be run by trusted automation or operators with
deployment access. Evidence records include provenance fields so the producer
can be identified later:

- `source_type`
- `source_name`
- `source_reference`
- `runtime_environment`

## Environment Isolation

Evidence is tagged by environment and never promoted implicitly:

- `local`
- `test`
- `ci`
- `staging`
- `production`

A CI or staging run does not make a production control healthy.

## CI Integration

The CI producer records evidence for the controls exercised by the auth/security
workflow, including:

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

The workflow records evidence only after the suite, Django checks, and migration
drift check have passed.

Important distinction:

- the GitHub Actions step proves the producer contract in the workflow's
  disposable test database
- durable environment evidence is written by running the same trusted management
  command inside the target environment

## CI Control Mappings

- refresh lifecycle suites map to refresh-rotation and replay-protection
- session suites map to server authority and logout-all revocation
- OTP/auth contract suites map to TOTP and reset enumeration protection
- step-up suites map to assurance step-up
- abuse-control suites map to PostgreSQL-backed abuse enforcement
- security audit suites map to durable security events and Observatory access

## CI PASS Behavior

A verified CI run creates `CI_RESULT` evidence with `PASS` result. The evidence
is valid for a limited time so it cannot remain healthy forever without fresh
verification.

Current default freshness:

- CI evidence: 7 days

## CI FAIL Behavior

A real failing CI assessment can create `FAIL` evidence for the relevant
control. Failures are not hidden by omission.

Repeated fail ingestion for the same control and source identity reuses the
same evidence record for that execution and updates the existing finding.

## CI Freshness

Expired CI pass evidence does not remain healthy indefinitely. The evaluator
reduces a stale control to `NEEDS_ATTENTION`.

## CI Idempotency

Evidence deduplicates on the producer identity and source reference for a given
control and evidence type. Re-running the exact same execution does not create a
duplicate row.

Different runs append new evidence.

## Configuration Integration

The configuration producer checks allowlisted runtime settings only:

- `AUTH_SESSION_ENFORCEMENT`
- `ABUSE_CONTROL_ENFORCEMENT`
- `JWT_REFRESH_ROTATION_ENABLED`

The checks are deterministic and do not dump the full environment.

## Configuration Checks

- `check_auth_session_enforcement`
- `check_abuse_control_enforcement`
- `check_refresh_rotation_enabled`

## Configuration Control Mappings

- `AUTH_SESSION_ENFORCEMENT = ENFORCE` -> `GAIT.SESSION.SERVER_AUTHORITY`
- `ABUSE_CONTROL_ENFORCEMENT = ENFORCE` -> `GAIT.ABUSE.POSTGRES_ENFORCEMENT`
- `JWT_REFRESH_ROTATION_ENABLED = True` -> `GAIT.AUTH.REFRESH_ROTATION`

## Secure Config Result

When the setting matches the expected value, the control receives `PASS`
evidence and may evaluate to `HEALTHY`.

## Unsafe Config Result

If the setting is unsafe or drifted, the control receives `FAIL` evidence and
the evaluator may move the control to `CONTROL_FAILURE`.

## Secret Configuration Review

The configuration producer does not persist or print secret values such as:

- database credentials
- API keys
- OAuth secrets
- JWT secrets
- passwords

Only safe conclusions and allowlisted setting names are written.

## Runtime Checks

Migration drift and Django system checks are verified as operational checks,
but they are only mapped to evidence when a legitimate control exists. Otherwise
they remain verification outputs for later use.

## SecurityEvent Evidence Use

`SECURITY_EVENT` evidence is supported, but it must remain narrow. A single
successful event does not prove a broad control healthy unless the evidence
producer explicitly says so.

## Finding Creation

`FAIL` evidence may create or update a deterministic `SecurityFinding` keyed to
the control and producer condition.

## Finding Deduplication

Repeated detection of the same failure updates the existing open finding instead
of creating a new one.

## Finding Recovery / Resolution

For machine-generated findings, a verified recovery `PASS` auto-resolves the
open finding if it is still open or acknowledged.

## Producer Failure Behavior

If a producer crashes or cannot complete a check, it must not emit `PASS`.
The safe default is no evidence rather than a false positive.

## Management Commands

- `manage.py security_collect_evidence`
- `manage.py security_check_configuration`

Both commands use the canonical operational-evidence layer and avoid secret
output.

For durable staging or production evidence, run these commands inside the
target Heroku environment rather than relying on the ephemeral CI database.

## Evidence API Impact

The public Observatory API remains read-only. The new evidence producers only
write through internal management commands and trusted automation.

## Rollout Model

The first rollout writes CI-backed evidence in the CI environment and allows
operators to run configuration checks in staging or production when appropriate.
Evidence stays environment-specific and append-oriented.
