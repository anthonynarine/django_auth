# Security Posture

This document tracks what's actually been hardened, what's a deliberate deferred trade-off (and why), and what would need to change to close it. Written after a full review pass — treat this as the source of truth over any older assumptions in code comments.

## Hardened

### Rate limiting

Login, OTP verification, and password-reset requests are throttled to **5 requests/minute per client** via DRF's `ScopedRateThrottle` (`authentication/settings.py`, `REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]`). Before this, none of these endpoints had any limit — a 6-digit TOTP code (1,000,000 combinations) or a user's password were both brute-forceable with no friction. `ScopedRateThrottle` is a no-op for any view that doesn't set `throttle_scope`, so enabling it globally didn't touch unrelated views.

Caveat: throttle counters live in Django's default cache (`LocMemCache` unless overridden), which is per-process. On a multi-dyno or multi-worker deployment, this is a soft limit, not a hard one — each process tracks its own count. Good enough to blunt casual brute forcing; not a substitute for a shared cache (Redis/Memcached) if this service scales horizontally.

### Password reset token expiry

`ResetPasswordRequestView` now calls `PasswordResetTokenGenerator().check_token(user, token)` before honoring a reset. Previously, the token was generated with Django's standard time-limited generator but never actually *checked* for expiry — only looked up by exact string match — so a reset link was valid indefinitely until used once. `PASSWORD_RESET_TIMEOUT = 3600` (1 hour) now bounds this.

### Secrets scrubbed from logs

Removed every log statement that printed a raw password, JWT (access/refresh/temp), OTP code, the `JWT_REFRESH_SECRET` value itself, full cookie dicts, request headers (which can carry a live `Authorization: Bearer <token>`), or a password-reset link (which embeds the reset token). These were all at `DEBUG`/`INFO` level across `user/views.py` and `user/auth_token.py`. If log output is ever centralized, shared, or leaked (Heroku log drains, `debug.log` on disk), none of these values are recoverable from it anymore.

### CLI secret handling

Operational secrets and temporary credentials MUST NOT be passed inline in Heroku or other process CLI arguments. Use environment variables, stdin, or interactive prompts instead of command-line flags or literal arguments that could be captured by process listings or platform logs.

### CSRF exemption is now an explicit allowlist

`DisableCSRFMiddleware` used to exempt **all** of `/api/*` unconditionally. It's now an explicit list of the specific endpoints that need it. Behavior is unchanged for every endpoint that exists today — this is a defense-in-depth change, not a new restriction — but a future endpoint added to `user/urls.py` no longer inherits CSRF exemption automatically; it has to be added to the allowlist deliberately.

## Deliberate, deferred trade-offs

### Full cookie-based CSRF protection doesn't work here — and that's structural, not a bug

The frontend (`gaitobservatory.com`) and this API (`herokuapp.com`) are on **different registrable domains** — genuinely cross-site. That breaks the standard double-submit-cookie CSRF pattern in a way no server-side configuration can fix: a `Set-Cookie` from this backend is invisible to the frontend's own JavaScript (`document.cookie` reads are blocked cross-origin by the browser, independent of any `SameSite` setting). The frontend's `axios.js` already has `X-CSRFToken` handling wired up — it just can never actually read the cookie value it would need to send.

**Why this isn't as exposed as it sounds:** `TokenAuthenticationMiddleware` forces `request.user` to `AnonymousUser` on any non-exempt path whenever no JWT is present. The real access token lives in a cookie scoped to the *frontend's* domain, which a cross-site attacker's page can neither read nor forge — and the only way it reaches this API is via an explicit `Authorization` header the legitimate frontend JS constructs itself. State-changing endpoints are effectively gated by a bearer token an attacker can't get at, as a side effect of this middleware design rather than by deliberate architecture.

**The actual fix** is a same-domain reverse proxy (frontend and API served from the same registrable domain), which is already on the roadmap. Once that lands, `HttpOnly` cookies and real CSRF tokens become viable and this whole class of concern goes away. Attempting a partial fix before then (e.g., flipping on Django's CSRF check for more endpoints) would only break legitimate requests, since the frontend has no way to obtain a valid token to send back — not close any real gap.

### Tokens are stored in JS-readable cookies, not `HttpOnly`

`access_token` / `refresh_token` are stored via `js-cookie` in the frontend and read by JavaScript to build the `Authorization` header. This means an XSS bug on the frontend could read and exfiltrate them. This is a common, accepted pattern for SPAs whose API lives on a different domain than the frontend (the alternative, `HttpOnly` cross-site cookies, is unreliable — see above, and increasingly blocked by browsers as third-party cookies regardless). React's default JSX escaping provides a reasonable baseline against the most common XSS vectors, though no dedicated XSS audit of the frontend has been done. The access token's 15-minute lifetime caps the blast radius of a theft. This is deferred to the same reverse-proxy work above, which is the point at which `HttpOnly` becomes practical.

## Known, lower-priority gaps (not yet addressed)

- **Weak password policy** — only `UserAttributeSimilarityValidator` and an 8-character minimum are active; a common-password blocklist is commented out in `settings.py` with an unfinished `# TODO`.
- **No account lockout** after repeated failed logins (rate limiting reduces, but doesn't eliminate, brute-force risk).
- **No explicit `SECURE_SSL_REDIRECT` / HSTS** configuration in `settings.py` (some of this may be covered by `django-heroku`'s defaults — not independently verified).
- **Access tokens are not revocable** — by design (a 15-minute JWT is short-lived enough that this is a reasonable trade-off), but worth remembering if that lifetime is ever extended.
