# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository context

This is a standalone Django REST authentication service (`Lume_Authentication/django_auth`). It is developed and deployed independently of the main Lumen application (see the top-level `Lumen/CLAUDE.md`), though it issues the JWTs that other Lumen services (e.g. `ExternalJWTAuthentication` in `lumen_reports`) are expected to validate. Do not assume Lumen's conventions apply here unless verified in this repo.

## Common Commands

```bash
# Activate the venv (Windows)
auth_venv\Scripts\activate

# Run the dev server
python manage.py runserver

# Migrations
python manage.py makemigrations
python manage.py migrate

# Tests (Django's test runner, not pytest)
python manage.py test
python manage.py test user.test_middleware
python manage.py test user.test_middleware.TokenAuthenticationMiddlewareTest
```

Required environment variables (see `.env`, not committed): `SECRET_KEY`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `JWT_TEMP_SECRET`, `DEFAULT_FROM_EMAIL`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `CLOUDAMQP_URL`, `POSTGRESQL_DB_*`, `REACT_APP_BASE_URL_DEV`/`_PROD`. The app hard-exits at startup (`authentication/settings.py`) if either JWT secret is missing.

Deployment is Heroku (`Procfile` runs `gunicorn authentication.wsgi`, `django_heroku` wires up Postgres/logging in `settings.py`); locally it falls back to a `DATABASE_URL` or direct Postgres config via `dj_database_url`/`decouple`, not sqlite, despite `db.sqlite3` being present in the repo.

## Architecture

### Three-app Django project
- `authentication/` — project root: settings, root `urls.py`, and custom middleware.
- `user/` — the actual auth domain: `CustomUser` model, JWT issuance/validation, login/2FA/password-reset views, RabbitMQ event producer.
- `mail/` — a single generic SMTP email endpoint (`/mail/send-email/`), decoupled from the `user` app's own transactional emails.

### Dual authentication mechanisms (both active, doing overlapping jobs)
1. **`TokenAuthenticationMiddleware`** (`authentication/custom_middleware/token_auth.py`) — runs on every request, reads a JWT from the `access_token` cookie (falling back to the `Authorization: Bearer` header), decodes it, and sets `request.user` directly. Paths in its `EXEMPT_PATHS` list skip this entirely. This middleware itself returns 401 JSON responses on invalid/expired tokens — it does not delegate to DRF exception handling.
2. **`JWTAuthentication`** (`user/auth_token.py`, a DRF `BaseAuthentication`) — used explicitly by views like `ValidateSessionAPIView` and `whoami_view` via `authentication_classes`, reading only the `Authorization` header.

Because both exist, a request's authenticated user can be resolved by either layer depending on the view — check `authentication_classes` on the view in question before assuming which path applies. Note the client-facing contract is currently inconsistent: `LoginAPIView`/`RefreshAPIView`/`TwoFactorLoginAPIView` return tokens in the **JSON response body** (not as cookies), while the middleware and `middleware.md` docs describe cookie-based (`access_token`/`refresh_token`) auth. Recent commit history (`f26dfc2`) indicates refresh-flow bugs are actively being tracked down here — verify current token transport (cookie vs. header vs. body) empirically rather than trusting `middleware.md`, which is stale.

`DisableCSRFMiddleware` unconditionally disables CSRF enforcement for any `/api/` path.

### Token types (`user/auth_token.py`)
Three distinct JWTs, each with its own secret and lifetime:
- **Access token** — 15 min, signed with `JWT_ACCESS_SECRET`, carries `user_id`/`email`/`role`.
- **Refresh token** — 7 days, signed with `JWT_REFRESH_SECRET`, persisted server-side in the `UserToken` model (so refresh tokens are revocable/lookup-checked, unlike access tokens).
- **Temporary 2FA token** — 10 min, signed with `JWT_TEMP_SECRET`, issued mid-login while awaiting OTP verification (`TwoFactorLoginAPIView`), carries `type: "2FA_temporary"` rather than a role.

### Auth flow (login → optional 2FA → tokens)
`LoginAPIView` authenticates email/password via Django's `authenticate()`, then branches: if `user.is_2fa_enabled`, it issues only a `temp_token` cookie and expects the client to call `TwoFactorLoginAPIView` with an OTP; otherwise it issues access+refresh tokens immediately. 2FA setup itself is a separate two-step flow: `Toggle2FAAPIView` (PATCH, sets `is_2fa_setup_in_progress`) → `GenerateQRCodeAPIView` (returns a PNG QR code from `pyotp`) → `Verify2FASetupAPIView` (validates the first OTP, flips `is_2fa_enabled` on, and rotates refresh/access tokens). `CustomUser.is_2fa_setup_in_progress` left dangling from an abandoned setup is reset back to disabled on next successful login.

### Roles
`user/roles.py` defines `RoleChoices` (`admin`, `physician`, `technologist`), stored on `CustomUser.role` and embedded directly in access/refresh token payloads — role is available to consumers without a DB round trip.

### Side effects on registration
`RegisterAPIView` does two things beyond creating the user: publishes a `user_events` fanout message to RabbitMQ via `user/rabbitmq_producer.py` (uses `CLOUDAMQP_URL`), and sends a "thank you" email using the `templates/email/` templates. Both are best-effort — failures are logged, not raised, so registration succeeds even if RabbitMQ/SMTP email fail.

### Password reset
Stateless-looking but stateful: `ForgotPasswordRequestView` always returns the same generic success message (to avoid email enumeration) but only actually creates a `Reset` record and sends an email if the address exists. `ResetPasswordRequestView` looks up by the reset token (not by user/uid), then deletes the `Reset` row after use — tokens are single-use.
