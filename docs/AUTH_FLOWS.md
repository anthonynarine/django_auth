# Authentication Flows

Every flow the API supports, end to end. All request/response shapes are exact — pulled from `user/views.py`, not approximated.

## Registration

```mermaid
sequenceDiagram
    participant U as User
    participant FE as React SPA
    participant API as Django API
    participant MQ as RabbitMQ
    participant SMTP as SMTP email

    U->>FE: Fill registration form
    FE->>API: POST /api/register/ {email, first_name, last_name, password, password_confirm}
    API->>API: Validate email format + uniqueness
    API->>API: Validate password (Django validators, min 8 chars)
    API->>API: Create CustomUser (password hashed via set_password)
    API-->>MQ: publish to "user_events" fanout exchange (best-effort)
    API-->>SMTP: send thank-you email (best-effort)
    API-->>FE: 201 Created + serialized user
```

Both the RabbitMQ publish and the SMTP email send are **best-effort** — failures are logged, never raised. Registration succeeds even if either downstream system is unreachable.

## Login (2FA disabled — the common case)

```mermaid
sequenceDiagram
    participant FE as React SPA
    participant API as Django API
    participant DB as PostgreSQL

    FE->>API: POST /api/login/ {email, password}
    Note over API: throttled: 5 requests / min per client
    API->>API: authenticate(username=email, password=password)
    alt invalid credentials
        API-->>FE: 401 {"error": "Invalid email or password"}
    else valid, 2FA enabled
        API->>API: issue temp_token (10 min, JWT_TEMP_SECRET)
        API-->>FE: 401 {"2fa_required": true} + temp_token cookie
        Note over FE: continues at "Login with 2FA" below
    else valid, 2FA disabled
        API->>API: create_access_token() — 15 min
        API->>API: create_refresh_token() — 7 days
        API->>DB: UserToken.objects.create(...)
        API-->>FE: 200 {"access_token": "...", "refresh_token": "..."}
    end
```

## Login with 2FA

```mermaid
sequenceDiagram
    participant FE as React SPA
    participant API as Django API
    participant DB as PostgreSQL

    Note over FE,API: Continues from Login above — temp_token cookie already set
    FE->>FE: Prompt user for 6-digit authenticator code
    FE->>API: POST /api/two-factor-login/ {otp} (temp_token cookie sent automatically)
    Note over API: throttled: 5 requests / min per client
    API->>API: decode temp_token (JWT_TEMP_SECRET)
    API->>API: pyotp.TOTP(user.tfa_secret).verify(otp)
    alt OTP valid
        API->>API: create_access_token() + create_refresh_token()
        API->>DB: UserToken.objects.create(...)
        API-->>FE: 200 {"access_token", "refresh_token"} + csrftoken cookie
    else OTP invalid or temp_token expired
        API-->>FE: 401 Authentication failed
    end
```

## 2FA setup (first time)

```mermaid
sequenceDiagram
    participant U as User
    participant FE as React SPA
    participant API as Django API

    FE->>API: PATCH /api/user/toggle-2fa/ {is_2fa_enabled: true}
    API->>API: user.is_2fa_setup_in_progress = true
    API-->>FE: 200 {"is_2fa_setup_in_progress": true}

    FE->>API: GET /api/generate-qr/  (requires an active session + recent step-up)
    alt assurance insufficient
        API-->>FE: 403 {"code": "STEP_UP_REQUIRED", "required_strength": "password"}
        Note over FE: prompt user for reauthentication
    else assurance sufficient
        API->>API: generate tfa_secret if none exists (pyotp.random_base32)
        API->>API: build otpauth:// provisioning URI, render as QR PNG
        API-->>FE: image/png
    end

    U->>U: Scan QR code in authenticator app

    FE->>API: POST /api/verify-otp/ {otp}
    API->>API: evaluate step-up + verify OTP
    alt OTP correct
        API->>API: is_2fa_enabled = true, is_2fa_setup_in_progress = false
        API->>API: delete old refresh token, issue new access + refresh tokens
        API-->>FE: 200 new tokens + csrftoken cookie
    else OTP incorrect or assurance insufficient
        API-->>FE: 400/403 {"error": {"otp": "Invalid OTP. Please try again"}} or STEP_UP_REQUIRED
    end
```

If a user starts this flow and abandons it, `is_2fa_setup_in_progress` is left dangling `true` — it gets silently reset to a clean disabled state on their **next successful login** (see the "Check if the 2FA setup was incomplete" step in `LoginAPIView`).

## Generalized step-up / reauthentication

```mermaid
sequenceDiagram
    participant FE as React SPA
    participant API as Django API
    participant AS as AuthSession

    FE->>API: sensitive action (e.g. change password, MFA disable)
    API->>AS: evaluate step-up requirement
    alt assurance sufficient
        API-->>FE: 200/202 as appropriate
    else assurance insufficient
        API-->>FE: 403 {"code": "STEP_UP_REQUIRED", "required_strength": "password|mfa"}
        FE->>FE: open reauthentication UI
        FE->>API: POST /api/reauthenticate/ {current_password, otp?}
        API->>API: verify proof against current session
        alt proof valid
            API->>AS: update recent_auth_at (+ strength if proven)
            API-->>FE: 200 {"message": "Reauthenticated"}
        else proof invalid
            API-->>FE: 400/401/403 failure
        end
    end
```

This is the shared path for sensitive operations. Password change and MFA lifecycle actions now use the same underlying assurance rules instead of bespoke freshness checks.

## Token refresh

```mermaid
sequenceDiagram
    participant FE as React SPA (axios interceptor)
    participant API as Django API
    participant DB as PostgreSQL

    FE->>API: Any authenticated request, access_token expired
    API-->>FE: 401 Unauthorized
    FE->>API: POST /api/token-refresh/ — Authorization: Bearer <refresh_token>
    Note over API: Reads the token from the header ONLY — never the request body
    API->>API: decode_refresh_token() — verify against JWT_REFRESH_SECRET
    API->>DB: UserToken.objects.filter(user, token, expired_at__gt=now).exists()
    alt token valid, unrevoked, unexpired
        API->>API: create_access_token() — new 15-minute token
        API-->>FE: 200 {"access_token": "..."}
        FE->>API: retries the original request with the new access token
    else invalid, revoked, or expired
        API-->>FE: 401 "unauthenticated"
        FE-->>FE: forces logout — no silent retry loop
    end
```

Note: `RefreshAPIView` only ever returns a **new access token** — refresh tokens are not rotated on use.

## Forgot / reset password

```mermaid
sequenceDiagram
    participant U as User
    participant FE as React SPA
    participant API as Django API
    participant SMTP as SMTP email

    U->>FE: Enter email
    FE->>API: POST /api/forgot-password/ {email}
    Note over API: throttled: 5 requests / min per client
    alt email not registered
        API-->>FE: 200 generic "if registered, you'll receive a link" message
        Note over API: Deliberately identical response either way — prevents email enumeration
    else email registered
        API->>API: PasswordResetTokenGenerator().make_token(user)
        API->>API: Reset.objects.create(email, token)
        API-->>SG: send reset email with link
        API-->>FE: 200 generic success message
    end

    U->>FE: Open email, click link, enter new password
    FE->>API: POST /api/reset-password/ {password, password_confirm, token}
    API->>API: Reset.objects.get(token=token) -> look up user by email
    API->>API: PasswordResetTokenGenerator().check_token(user, token)
    Note over API: Verifies authenticity AND that it's within PASSWORD_RESET_TIMEOUT (1 hour)
    alt token valid and unexpired
        API->>API: user.set_password(new_password)
        API->>API: delete the Reset row — single-use
        API-->>FE: 202 {"message": "Password updated"}
    else token invalid, forged, or expired
        API-->>FE: 400 {"error": "This password reset link is invalid or has expired."}
    end
```

## Logout

```mermaid
sequenceDiagram
    participant FE as React SPA
    participant API as Django API
    participant DB as PostgreSQL

    FE->>API: POST /api/logout/ (refresh_token cookie, if present)
    API->>DB: UserToken.objects.filter(token=refresh_token).delete()
    API->>API: Django logout() — clears the session
    API-->>FE: 200 {"message": "Signed out"}
    FE-->>FE: clears its own access/refresh/csrf cookies
```
