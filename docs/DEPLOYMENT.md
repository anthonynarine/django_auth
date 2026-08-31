# Deployment

This service deploys to **Heroku**. Locally, it runs against a direct Postgres connection instead of SQLite — `db.sqlite3` is present in the repo but not what the app actually uses (see `authentication/settings.py`'s `DATABASES` block).

## How it ships

- **`Procfile`** — `web: gunicorn authentication.wsgi`
- **`runtime.txt`** — `python-3.11.8`
- **`django-heroku`** — `django_heroku.settings(locals())` is called at the bottom of `settings.py`, which wires up Postgres connection pooling and Heroku-appropriate logging automatically from the `DATABASE_URL` config var.
- **Static files** — served via WhiteNoise (`whitenoise.middleware.WhiteNoiseMiddleware`), `STATICFILES_STORAGE` set to `CompressedManifestStaticFilesStorage`.

## Deploying

```bash
# From the django_auth root, assuming a Heroku remote is configured
git push heroku main

# Migrations don't run automatically — apply them explicitly
heroku run python manage.py migrate
```

## Config vars

All variables in [`ENVIRONMENT.md`](ENVIRONMENT.md) must be set as Heroku config vars (`heroku config:set KEY=value`), **except** `DATABASE_URL`, which Heroku Postgres sets automatically when the add-on is attached — don't set `POSTGRESQL_DB_*` vars on Heroku; `DATABASE_URL` takes priority in `settings.py` when present.

Double-check `DEBUG=False` is set on Heroku — the app's cookie security settings (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_SAMESITE`, etc.) branch on this in `settings.py`, and running production with dev-mode cookie settings would weaken transport security for session/CSRF cookies.

## Known constraints worth remembering before scaling

- **Rate-limit counters are per-process** (`LocMemCache` by default) — see [`SECURITY.md`](SECURITY.md#rate-limiting). If this service ever runs multiple dynos or multiple gunicorn workers, throttling becomes a soft, per-process limit rather than a hard global one. Moving to a shared cache (Redis/Memcached) would be the fix if that becomes a problem.
- **RabbitMQ (CloudAMQP) and SMTP email calls are synchronous** inside the request/response cycle for `RegisterAPIView` and `ForgotPasswordRequestView` — a slow or unreachable external service adds latency to those endpoints, even though failures don't block the response.
