# Environment Variables

All read via `python-decouple` (`config(...)`) from a local `.env` file, or from Heroku config vars in production. None are committed — see `.gitignore`. The app **hard-exits at startup** if either JWT secret is missing (`authentication/settings.py`).

## Required

| Variable | Used in | Purpose |
|---|---|---|
| `SECRET_KEY` | `settings.py` | Django's own signing key (sessions, password-reset tokens, etc.) |
| `JWT_ACCESS_SECRET` | `settings.py`, `auth_token.py` | Signs/verifies 15-minute access tokens. **App exits at startup if unset.** |
| `JWT_REFRESH_SECRET` | `settings.py`, `auth_token.py` | Signs/verifies 7-day refresh tokens. **App exits at startup if unset.** |
| `JWT_TEMP_SECRET` | `auth_token.py` | Signs/verifies the 10-minute 2FA temporary token |
| `DEFAULT_FROM_EMAIL` | `settings.py` | From-address for outgoing application mail. Required when `DEBUG=False`; defaults locally. |
| `EMAIL_HOST_USER` | `settings.py` | SMTP username for outgoing application mail. Required when `DEBUG=False`; optional locally. |
| `EMAIL_HOST_PASSWORD` | `settings.py` | SMTP password or provider app password for outgoing application mail. Required when `DEBUG=False`; optional locally. |
| `CLOUDAMQP_URL` | `rabbitmq_producer.py` | RabbitMQ connection string for the `user_events` fanout exchange |
| `POSTGRESQL_DB_NAME` | `settings.py` | Local/non-Heroku Postgres connection |
| `POSTGRESQL_DB_USER` | `settings.py` | Local/non-Heroku Postgres connection |
| `POSTGRESQL_DB_PASSWORD` | `settings.py` | Local/non-Heroku Postgres connection |
| `REACT_APP_BASE_URL_DEV` | `settings.py` | Frontend base URL used to build password-reset links when `DEBUG=True` |
| `REACT_APP_BASE_URL_PROD` | `settings.py` | Frontend base URL used to build password-reset links when `DEBUG=False` |

## Optional (have defaults)

| Variable | Default | Purpose |
|---|---|---|
| `DEBUG` | `True` | Toggles dev vs. production cookie/CSRF security settings — **set explicitly to `False` in production** |
| `POSTGRESQL_DB_HOST` | `localhost` | Postgres host, when not using `DATABASE_URL` |
| `POSTGRESQL_DB_PORT` | `5432` | Postgres port, when not using `DATABASE_URL` |
| `EMAIL_HOST` | `smtp.zoho.com` | SMTP host for outgoing application mail |
| `EMAIL_PORT` | `587` | SMTP port for outgoing application mail |
| `EMAIL_USE_TLS` | `True` | Whether SMTP uses STARTTLS |
| `EMAIL_BACKEND` | `console backend when `DEBUG=True`; SMTP backend when `DEBUG=False` | Email backend |

## Heroku-provided (not in `.env`)

| Variable | Source | Purpose |
|---|---|---|
| `DATABASE_URL` | Set automatically by Heroku Postgres | When present, takes priority over the individual `POSTGRESQL_DB_*` vars (`dj_database_url.config(...)`) |

## What breaks without each one

- Missing `JWT_ACCESS_SECRET` or `JWT_REFRESH_SECRET` → the process refuses to start at all (`sys.exit(1)` in `settings.py`).
- Missing `DEFAULT_FROM_EMAIL`, `EMAIL_HOST_USER`, or `EMAIL_HOST_PASSWORD` in production (`DEBUG=False`) → the process refuses to start because SMTP settings are required by `settings.py`.
- Missing SMTP credentials locally (`DEBUG=True`) → Django uses console email by default, so password-reset emails print to the development server output instead of sending.
- Missing `CLOUDAMQP_URL` → the RabbitMQ publish on registration fails silently (best-effort; logged, not raised).
- Wrong `REACT_APP_BASE_URL_DEV` / `_PROD` → password-reset emails link to the wrong frontend origin.
- `DEBUG` left `True` in production → cookies get `Secure=False` / `SameSite=Lax` instead of the production-appropriate settings. Confirm this is `False` on Heroku.

## Current production frontend origin

The primary frontend origin is:

```text
https://gaitobservatory.com
```

`https://gait.netlify.app` remains temporarily allowed during the Netlify custom-domain cutover.
