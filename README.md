# django_auth
Authenticate with Access &amp; Refresh Tokens, 2FA, Social Authentication with Google.

# API Documentaion 
https://documenter.getpostman.com/view/23868442/2sA2xh3tTu


# Application Overview
The application provides user registration, login, password reset, and JWT token authentication functionalities. It utilizes Django's user model, custom user model extensions, JWT for token management, and Django Rest Framework for creating API endpoints.

### 1. Models

#### CustomUser

- **File**: `models.py`
- **Purpose**: Extends Django's `AbstractUser` to use email as the primary user identifier instead of a username.
- **Key Attributes**:
  - `email`: Used for authentication instead of `username`.
  - `first_name` and `last_name`: Store the user's name.

```python
class CustomUser(AbstractUser):
    email = models.EmailField(_("email address"), unique=True)
    first_name = models.CharField(max_length=26)
    last_name = models.CharField(max_length=26)
    password = models.CharField(max_length=26)
    username = None

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()
```

#### UserToken

- **Purpose**: Stores refresh tokens for users, allowing them to get a new access token without re-authenticating.
- **Key Attributes**:
  - `user`: ForeignKey linking to the `CustomUser`.
  - `token`: The refresh token string.
  - `expired_at`: Expiry date of the token.

#### Reset

- **Purpose**: Used for password reset functionalities. It stores a token sent to the user's email for resetting their password.
- **Key Attributes**:
  - `email`: The email address requesting a password reset.
  - `token`: The token sent to the user's email for password reset validation.

### 2. Views & Authentication

#### RegisterAPIView

- **File**: `views.py`
- **Method**: `post`
- **Functionality**: Handles user registration. Validates passwords, saves the user, and returns the user data.

#### LoginAPIView

- **Method**: `post`
- **Functionality**: Authenticates the user by email and password. Generates and returns an access token, and stores a refresh token as a cookie.

#### RefreshAPIView

- **Method**: `post`
- **Functionality**: Uses the refresh token to issue a new access token for authenticated users.

#### LogoutAPIView

- **Method**: `post`
- **Functionality**: Deletes the user's refresh token and clears the cookie, effectively logging them out.

#### ForgotPasswordRequestView & ResetPasswordRequestView

- **Functionality**: Handle the password reset flow. The former sends an email with a reset link, and the latter resets the password using the token from the email.

### 3. JWT Token Management

#### create_access_token & create_refresh_token

- **Purpose**: Generate JWT access and refresh tokens for authentication and session management.
- **Implementation**: Uses `jwt.encode` to create tokens with user-specific payloads, including expiration times.

#### decode_access_token & decode_refresh_token

- **Purpose**: Decode and validate tokens, returning the user ID if valid.
- **Implementation**: Uses `jwt.decode` to verify token integrity and extract the payload.

### 4. URL Configuration

- **File**: `urls.py`
- **Purpose**: Maps endpoints to view functions, defining the API structure for authentication functionalities.

```
urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("refresh/", RefreshAPIView.as_view(), name="refresh"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("forgot-password/", ForgotPasswordRequestView.as_view(), name="forgot_password"),
    path("reset-password/", ResetPasswordRequestView.as_view(), name="reset_password"),
]
```



