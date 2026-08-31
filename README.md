# Gait — Django Authentication API

[![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-5.0-092E20?logo=django&logoColor=white)](https://www.djangoproject.com/)
[![DRF](https://img.shields.io/badge/DRF-3.14-A30000)](https://www.django-rest-framework.org/)
[![JWT](https://img.shields.io/badge/auth-JWT%20%2B%20TOTP%202FA-blueviolet)](https://pyjwt.readthedocs.io/)
[![Deployed](https://img.shields.io/badge/deployed-Heroku-430098?logo=heroku&logoColor=white)](https://ant-django-auth-62cf01255868.herokuapp.com/)

A standalone Django REST authentication service: registration, login, JWT access/refresh tokens, TOTP-based two-factor authentication, and password reset — built to be consumed by other services (like the [Lumen](https://github.com/anthonynarine) platform) as a central identity provider.

**Live API:** `https://ant-django-auth-62cf01255868.herokuapp.com/api`
**Reference frontend:** [gaitobservatory.com](https://gaitobservatory.com) ([AuthFlow](https://github.com/anthonynarine/AuthFlow) repo). The legacy Netlify subdomain, `https://gait.netlify.app`, remains temporarily allowed during the domain cutover.

---

## Contents

- [Features](#features)
- [Tech stack](#tech-stack)
- [Quick start](#quick-start)
- [Project layout](#project-layout)
- [API surface](#api-surface)
- [Testing](#testing)
- [Documentation](#documentation)

## Features

- **Email-based auth** — custom user model, no username field.
- **JWT access + refresh tokens** — short-lived (15 min) access tokens, DB-revocable 7-day refresh tokens.
- **Two-factor authentication** — TOTP via an authenticator app (`pyotp`), with a QR-code setup flow.
- **Password reset** — token-based, single-use, and time-limited.
- **Rate limiting** — login, OTP verification, and password-reset requests are throttled per client.
- **Role-aware tokens** — `admin` / `physician` / `technologist` roles are embedded directly in the JWT payload, so downstream services don't need a DB round trip to check them.
- **Best-effort side effects** — registration publishes a RabbitMQ event and sends a transactional email; neither failure blocks account creation.

## Tech stack

| Layer | Choice |
|---|---|
| Framework | Django 5.0 + Django REST Framework 3.14 |
| Auth tokens | PyJWT (HS256), custom-issued — not `django-rest-framework-simplejwt` |
| 2FA | `pyotp` (TOTP) + `qrcode` for setup |
| Database | PostgreSQL (via `dj-database-url` / `decouple`) |
| Email | SMTP transactional email |
| Async events | RabbitMQ (`pika`), CloudAMQP in production |
| Static files | WhiteNoise |
| Hosting | Heroku (`django-heroku`, `gunicorn`) |

## Quick start

```bash
# 1. Activate the virtual environment (Windows)
auth_venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment — see docs/ENVIRONMENT.md for the full reference
copy example.env .env    # then fill in real values

# 4. Run migrations
python manage.py migrate

# 5. Start the dev server
python manage.py runserver
```

The app **hard-exits at startup** if `JWT_ACCESS_SECRET` or `JWT_REFRESH_SECRET` is missing — see `authentication/settings.py`.

## Project layout

```
authentication/     Project root: settings, root urls.py, custom middleware
user/                Auth domain: CustomUser model, JWT issuance, login/2FA/reset views
mail/                Standalone generic SMTP email endpoint
docs/                Full system manual — architecture, flows, API reference, security notes
templates/email/     HTML templates for transactional emails
```

## API surface

All endpoints are namespaced under `/api/` (see `user/urls.py`) except the generic mail sender under `/mail/`. Full request/response detail lives in [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) — short version:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/register/` | POST | Create an account |
| `/api/login/` | POST | Authenticate; returns tokens or starts 2FA |
| `/api/two-factor-login/` | POST | Complete login with a TOTP code |
| `/api/token-refresh/` | POST | Exchange a refresh token for a new access token |
| `/api/logout/` | POST | Revoke the refresh token |
| `/api/forgot-password/` | POST | Email a password-reset link |
| `/api/reset-password/` | POST | Set a new password from a reset token |
| `/api/generate-qr/` | GET | Get a TOTP QR code for 2FA setup |
| `/api/verify-otp/` | POST | Confirm 2FA setup |
| `/api/user/toggle-2fa/` | PATCH | Start/stop the 2FA setup process |
| `/api/validate-session/` | GET | Return the current authenticated user |
| `/api/whoami/` | GET | Same as above, for external service integration |

## Testing

Uses Django's built-in test runner (not pytest):

```bash
python manage.py test                                  # full suite
python manage.py test user.test_middleware              # one module
python manage.py test user.test_security_patches         # security-hardening tests
```

## Documentation

The full manual — architecture diagrams, sequence diagrams for every auth flow, the API reference, environment variable reference, deployment notes, and the current security posture — lives in [`docs/`](docs/README.md).

---

© 2025 Anthony Narine. All rights reserved. Part of the Gait / Lumen authentication ecosystem.
