# API Reference

Base URL: `https://ant-django-auth-62cf01255868.herokuapp.com/api` in production, `http://127.0.0.1:8000/api` locally. All routes below are relative to that base except the `mail` endpoint, which sits outside `/api` at the project root.

Postman collection: [`Authentication.postman_collection.json`](../Authentication.postman_collection.json).

## Auth endpoints (`user/urls.py`)

### `POST /register/`

Create an account. No authentication required.

**Body:** `{ "email", "first_name", "last_name", "password", "password_confirm" }`
**201** → serialized user (password excluded)
**400** → `{"error": {...}}` — duplicate email, weak/mismatched password, or invalid format

---

### `POST /login/`

Authenticate with email + password. No authentication required. Protected by PostgreSQL-backed abuse control.

**Body:** `{ "email", "password" }`
**200** → `{ "message", "access_token", "refresh_token" }`
**401** → `{"2fa_required": true}` + `temp_token` cookie set, if 2FA is enabled on the account
**401** → `{"error": "Invalid email or password"}` on bad credentials
**400** → missing email/password
**429** → abuse threshold reached for the current login scope (`Retry-After` included)

---

### `POST /two-factor-login/`

Complete a login that returned `2fa_required`. Requires the `temp_token` cookie issued by `/login/`. **Throttled: 5/min per client.**

**Body:** `{ "otp" }`
**200** → `{ "message", "access_token", "refresh_token" }` + `csrftoken` cookie
**400** → missing OTP or temp_token
**401** → invalid/expired temp_token, or incorrect OTP
**429** → abuse threshold reached for the current OTP scope (`Retry-After` included)

---

### `POST /token-refresh/`

Exchange a refresh token for a new access token. **The refresh token must be sent in the `Authorization: Bearer <token>` header — the request body is not read.**

**200** → `{ "message", "access_token" }`
**401** → missing header, invalid/expired refresh token, or the token isn't found (unrevoked, unexpired) in the `UserToken` table

---

### `POST /logout/`

Revoke the current refresh token and clear the session. Reads `refresh_token` from cookies if present; safe to call even without one.

**200** → `{ "message": "Signed out" }`

---

### `POST /forgot-password/`

Request a password-reset email. No authentication required. Protected by PostgreSQL-backed abuse control.

**Body:** `{ "email" }`
**200** → always the same generic message, regardless of whether the email is registered (prevents enumeration)
**429** → abuse threshold reached for the current reset scope (`Retry-After` included)

---

### `POST /reset-password/`

Set a new password using a reset token from the emailed link.

**Body:** `{ "password", "password_confirm", "token" }`
**202** → `{ "message": "Password updated" }`
**400** → passwords don't match, fail Django's password validators, or the token is missing/invalid/**expired** (tokens are valid for 1 hour, see `PASSWORD_RESET_TIMEOUT`)

---

### `POST /change-password/`

Change the currently authenticated user's password. Requires an active session and recent step-up proof. The user supplies the current password plus a new password.

**Body:** `{ "current_password", "new_password", "new_password_confirm" }`
**200** → `{ "message": "Password changed successfully." }`
**400** → missing fields, mismatched passwords, wrong current password, or Django password-validator failure
**403** → `{"code": "STEP_UP_REQUIRED", ...}` when the current session is too stale or too weak
**429** → abuse threshold reached for the current reauthentication/password-change scope (`Retry-After` included)

---

### `POST /reauthenticate/`

Refresh recent-auth assurance without creating a new session. Requires an active authenticated session.

**Body:** `{ "current_password", "otp"? }`
**200** → `{ "message": "Reauthenticated successfully." }` and the session's `recent_auth_at` is updated
**400** → missing current password, wrong current password, or invalid OTP
**403** → `{"code": "STEP_UP_REQUIRED", ...}` when the current session is too stale or too weak
**429** → abuse threshold reached for the current reauthentication scope (`Retry-After` included)

---

### `GET /generate-qr/`

Return a PNG QR code for setting up 2FA in an authenticator app. Requires an active session and recent step-up proof. Generates and persists `tfa_secret` on first call if none exists.

**200** → `image/png`
**403** → `{"code": "STEP_UP_REQUIRED", ...}` when the current session is too stale or too weak

---

### `POST /verify-otp/`

Confirm 2FA setup with the first OTP from the authenticator app. Requires an active session and the step-up state required by the setup flow.

**Body:** `{ "otp" }`
**200** → `{ "message", "access_token", "refresh_token" }` + `csrftoken` cookie — enables 2FA and rotates tokens
**400** → `{"error": {"tfa_setup": "2FA is not set up."}}` if setup was never started, or `{"error": {"otp": "..."}}` on a wrong code
**403** → `{"code": "STEP_UP_REQUIRED", ...}` when the current session is too stale or too weak
**429** → abuse threshold reached for the current OTP scope (`Retry-After` included)

---

### `PATCH /user/toggle-2fa/`

Start or stop the 2FA setup process. Requires an authenticated `request.user` (set by `TokenAuthenticationMiddleware`).

**Body:** `{ "is_2fa_enabled": true | false }`
**200** → `{ "is_2fa_setup_in_progress": bool }`
**401** → not authenticated
**400** → missing `is_2fa_enabled`

---

### `GET /validate-session/`

Return the currently authenticated user. Uses `JWTAuthentication` explicitly — reads the `Authorization` header only, ignores cookies.

**200** → serialized user
**401** → not authenticated

---

### `GET /whoami/`

Identical contract to `/validate-session/`, intended for external services (e.g. `ExternalJWTAuthentication` consumers in the Lumen platform) integrating against this identity provider.

**200** → serialized user
**401** → not authenticated

---

## Security Observatory (`security/urls.py`)

All of these routes are staff-only. Non-staff authenticated users receive `403`; anonymous callers receive the existing auth failure behavior.

### `GET /security/summary/`

Return a dashboard summary for the current window.

### `GET /security/events/`

Return a paginated, filterable list of `SecurityEvent` rows.

### `GET /security/events/{id}/`

Return one `SecurityEvent` row.

### `GET /security/sessions/`

Return a paginated list of active and historical `AuthSession` rows.

### `GET /security/sessions/{id}/`

Return one `AuthSession` row.

---

### `POST /test-csrf-exempt/`

Diagnostic endpoint confirming the CSRF-exemption allowlist is wired correctly. Not part of the product surface.

## Mail endpoint (`mail/urls.py`)

### `POST /mail/send-email/`

Generic SMTP email send, decoupled from the `user` app's own transactional emails.

**Body:** `{ "from_email", "to_email", "subject", "content" }`
**200** → `{ "message": "Email sent successfully" }`
**500** → SMTP email failure

## Serialized user shape

Returned by `/register/`, `/validate-session/`, `/whoami/` (`user/serializers.py`):

```json
{
  "id": 1,
  "first_name": "Ada",
  "last_name": "Lovelace",
  "email": "ada@example.com",
  "is_2fa_enabled": false,
  "role": "technologist",
  "is_staff": false
}
```

`password` is `write_only` — never present in a response.
