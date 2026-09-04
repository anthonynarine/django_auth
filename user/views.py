# Standard library imports
from datetime import timedelta
from io import BytesIO
import logging
import os

# Third-party imports
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model, authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.core.validators import validate_email
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMultiAlternatives
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.db import transaction
from django.db import IntegrityError
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.shortcuts import get_object_or_404
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import AnonymousUser
from django.middleware.csrf import get_token
from rest_framework.exceptions import ValidationError as DRFValidationError
from django.views.decorators.csrf import csrf_exempt

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated

import pyotp
import qrcode

from abuse.services import check as abuse_check, record_failure as abuse_record_failure, record_success as abuse_record_success
from authentication.settings import ACCESS_TOKEN_SAMESITE, REFRESH_TOKEN_SAMESITE
from security.models import SecurityEvent
from security.services import record_security_event

# Local application/library specific imports
from .auth_token import JWT_ACCESS_SECRET, create_access_token, JWTAuthentication, create_temporary_2fa_token, decode_temporary_token
from .models import CustomUser, UserToken, Reset
from .refresh_tokens import (
    issue_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
)
from .session_services import create_session, revoke_all_sessions, revoke_other_sessions
from .account_security_services import (
    change_password as perform_password_change,
    disable_mfa as perform_mfa_disable,
    reauthenticate_session,
    resolve_current_auth_session,
)
from .step_up import STEP_UP_POLICIES, require_step_up
from .serializers import CustomUserSerializer
from .guest import DEMO_USER_EMAIL
from .rabbitmq_producer import send_user_registered_message
from django.http import HttpResponse
from django.conf import settings

User = get_user_model()
print(User)

logger = logging.getLogger(__name__)
# Test logging
logger.debug("This is a debug message")
logger.info("This is an info message")
logger.warning("This is a warning message")
logger.error("This is an error message")
logger.critical("This is a critical message")

# ANSI color codes for logger
RED = '\033[91m'
GREEN = '\033[92m'
END = '\033[0m'

logger.debug("DEBUG mode is: %s", settings.DEBUG)


def _abuse_blocked_response(decision, *, message: str):
    response = Response({"error": message}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    if decision.retry_after_seconds:
        response["Retry-After"] = str(decision.retry_after_seconds)
    return response


def _first_blocked_abuse_decision(calls):
    for scope, kwargs in calls:
        decision = abuse_check(scope, **kwargs)
        if not decision.allowed:
            return decision
    return None


def _pick_abuse_decision(*decisions):
    if not decisions:
        return None
    ranking = {
        "NORMAL": 0,
        "THROTTLED": 1,
        "BLOCKED": 2,
    }
    return max(decisions, key=lambda decision: ranking.get(decision.state, 0))


def _login_abuse_call_args(*, request, email: str | None):
    calls = [("LOGIN_IP", {"request": request})]
    if email:
        calls.extend(
            [
                ("LOGIN_ACCOUNT", {"request": request, "account": email}),
                ("LOGIN_IP_ACCOUNT", {"request": request, "account": email}),
            ]
        )
    return calls


def _otp_abuse_call_args(*, request, user=None, session=None):
    calls = [("OTP_IP", {"request": request})]
    if user is not None:
        calls.append(("OTP_ACCOUNT", {"request": request, "user": user, "account": user.email}))
    if session is not None:
        calls.append(("OTP_SESSION", {"request": request, "user": user, "auth_session": session, "account": user.email}))
    return calls


def _password_reset_abuse_call_args(*, request, email: str | None):
    calls = [("PASSWORD_RESET_IP", {"request": request})]
    if email:
        calls.append(("PASSWORD_RESET_ACCOUNT", {"request": request, "account": email}))
    return calls


@method_decorator(csrf_exempt, name='dispatch')
class TestCSRFExemptView(APIView):
    def post(self, request):
        return Response({'message': 'CSRF exempt view works'}, status=200)

class RegisterAPIView(APIView):
    def post(self, request):
        """
        Register a new user.

        Validates the provided email, password, and password confirmation.
        Sends a thank you email upon successful registration.

        Args:
            request (Request): HTTP POST request containing user registration data.

        Returns:
            Response: HTTP response with user data and status code.
        """
        data = request.data.copy()  # Make a mutable copy of request data

        # Validate and normalize email
        email = data.get("email", "").strip().lower()
        if CustomUser.objects.filter(email=email).exists():
            return Response({"error": {"email": "This email is already in use"}}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_email(email)
            data["email"] = email
        except ValidationError:
            return Response({"error": {"email": "Invalid email format"}}, status=status.HTTP_400_BAD_REQUEST)

        # Validation for passwords
        password = data.get("password")
        password_confirm = data.get("password_confirm")
        if not password or not password_confirm:
            return Response({"error": {"password": "Password and password confirmation are required"}}, status=status.HTTP_400_BAD_REQUEST)
        if password != password_confirm:
            return Response({"error": {"password_confirm": "Passwords do not match"}}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": {"password": str(e)}}, status=status.HTTP_400_BAD_REQUEST)

        # Initialize the serializer with the modified data
        serializer = CustomUserSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            
            # Prepare the user data to send to RabbitMQ
            user_data = {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_2fa_enabled": user.is_2fa_enabled,
            }
            
            # Send the registration event to RabbitMQ
            send_user_registered_message(user_data)
                        
            # Send the thank you email
            self.send_thank_you_email(user.email)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except DRFValidationError as e:
            return Response({"error": e.get_full_details()}, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            return Response({"error": {"non_field_error": "A database error occurred"}}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": {"non_field_error": "An unexpected error occurred"}}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def send_thank_you_email(self, email):
        try:
            html_content = render_to_string("email/thank_you_email.html", {})
            text_content = strip_tags(html_content)
            subject = "Thank you for testing out this application"

            message = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, [email])
            message.attach_alternative(html_content, "text/html")
            message.send()
            logger.info(f"Welcome email sent to {email}")
        except Exception as e:
            logger.error(f"Failed to send welcome email to {email}: {e}", exc_info=True)

@method_decorator(csrf_exempt, name='dispatch')
class LoginAPIView(APIView):
    """
    API view that handles user login requests. This view validates user credentials,
    checks for two-factor authentication requirements, and manages the issuance of tokens.
    It supports the first step of login which involves username and password verification,
    and if 2FA is enabled, it issues a temporary token for further verification.

    Attributes:
        None

    Methods:
        post(request): Processes the POST request to log in a user.
    """

    permission_classes = [AllowAny]  # Allow access to any user regardless of their authentication status.
    def post(self, request):
        print("LoginAPIView: Request reached")
        """
        Handle POST request to authenticate a user.

        First, it validates the provided email and password. If authentication is successful,
        it checks whether 2FA is enabled for the user. If 2FA is enabled, it issues a temporary
        token and sets it in an HTTP-only cookie. Otherwise, it issues access and refresh tokens.

        Expects:
            request.data: Dictionary containing:
                - email (str): The user's email address.
                - password (str): The user's password.

        Parameters:
            request (HttpRequest): The request object containing the email and password.

        Returns:
            Response: Django REST Framework response object with either error message and status code
                    or successful login data and tokens.
        """
        data = request.data.copy()  # Copy data to prevent mutable data issues.
        email = data.get("email", "").strip().lower()  # Normalize email to ensure case-insensitive comparison.
        password = data.get("password")

        blocked = _first_blocked_abuse_decision(_login_abuse_call_args(request=request, email=email or None))
        if blocked:
            return _abuse_blocked_response(blocked, message="Login temporarily blocked.")

        # Check if both email and password are provided.
        if not email or not password:
            for scope, kwargs in _login_abuse_call_args(request=request, email=email or None):
                abuse_record_failure(scope, **kwargs)
            logger.info("Login attempt failed: Missing email or password.")
            record_security_event(
                SecurityEvent.EventType.LOGIN_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="MISSING_CREDENTIALS",
                request=request,
                metadata={"authentication_method": "password"},
            )
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate the user using username and password
        user = authenticate(username=email, password=password)
        if not user:
            for scope, kwargs in _login_abuse_call_args(request=request, email=email or None):
                abuse_record_failure(scope, **kwargs)
            # Log and respond if authentication fails
            logger.error("Authentication failed: Invalid email or password.")
            record_security_event(
                SecurityEvent.EventType.LOGIN_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="INVALID_PASSWORD",
                user=User.objects.filter(email=email).first(),
                request=request,
                metadata={"authentication_method": "password"},
            )
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        # Log the user in, which establishes the user's session.
        login(request, user)
        for scope, kwargs in _login_abuse_call_args(request=request, email=email or None):
            if scope == "LOGIN_IP":
                continue
            abuse_record_success(scope, **kwargs)

        # Check if the 2FA setup was incomplete and reset if necessary
        if user.is_2fa_setup_in_progress:
            user.is_2fa_enabled = False
            user.is_2fa_setup_in_progress = False
            user.tfa_secret = ''
            user.save(update_fields=["is_2fa_enabled", "is_2fa_setup_in_progress", "tfa_secret"])
            logger.info(f"2FA setup reset for user {user.username} due to incomplete setup.")

        # Check if 2FA is enabled for the user
        if user.is_2fa_enabled:
            try:
                # Create a temporary token specifically for 2FA verification
                temp_token = create_temporary_2fa_token(user.id)
                response = Response({'message': '2FA required', '2fa_required': True}, status=status.HTTP_401_UNAUTHORIZED)
                response.set_cookie("temp_token", temp_token, max_age=600, httponly=True, secure=True, samesite="None")  # Token expires in 10 minutes
                logger.info(f"2FA required for user {email}. Temporary token issued.")
                return response
            except Exception as e:
                # Handle exceptions related to temporary token creation
                logger.error(f"Failed to create temporary token for user {email}: {str(e)}")
                return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # If 2FA is not enabled, proceed with creating access and refresh tokens
        try:
            session = create_session(
                user,
                request=request,
                authentication_method="password",
                authentication_strength="password",
            )
            access_token = create_access_token(user.id, sid=session.id)
            issued_refresh = issue_refresh_token(user, request=request, auth_session=session)
            record_security_event(
                SecurityEvent.EventType.LOGIN_SUCCESS,
                outcome=SecurityEvent.Outcome.SUCCESS,
                severity=SecurityEvent.Severity.INFO,
                reason_code="PASSWORD_LOGIN",
                user=user,
                auth_session=session,
                request=request,
                metadata={"authentication_method": "password"},
            )
            # Keep broad LOGIN_IP history intact so one successful account
            # login does not erase a shared-IP abuse signal for other users.
            # LOGIN_ACCOUNT and LOGIN_IP_ACCOUNT remain cleared on success.
            response = Response({
                "message": "Logged in successfully.",
                "access_token": access_token,
                "refresh_token": issued_refresh.token
            }, status=status.HTTP_200_OK)
                        
            logger.info(f"Successful login for {email}. Full access tokens created and sent.")
            return response
        except Exception as e:
            # Handle exceptions related to full access token creation
            logger.error(f"Error creating tokens for user {email}: {str(e)}")
            return Response({'error': 'Unable to create tokens'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class GuestLoginAPIView(APIView):
    """
    Issues real access/refresh tokens for a fixed demo account, with no
    credentials required, so a portfolio visitor can try the app instantly.

    Backed by the account created/reset by the `seed_demo_user` management
    command. That account never has 2FA enabled, so this always returns
    tokens directly rather than branching into the 2FA flow like
    LoginAPIView does.
    """

    permission_classes = [AllowAny]
    def post(self, request):
        blocked = _first_blocked_abuse_decision([("LOGIN_IP", {"request": request})])
        if blocked:
            return _abuse_blocked_response(blocked, message="Guest login temporarily blocked.")

        try:
            user = User.objects.get(email=DEMO_USER_EMAIL)
        except User.DoesNotExist:
            logger.error("Guest login requested but the demo user does not exist. Run `manage.py seed_demo_user`.")
            return Response({"error": "Guest login is not available right now."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            session = create_session(
                user,
                request=request,
                authentication_method="guest",
                authentication_strength="guest",
            )
            access_token = create_access_token(user.id, sid=session.id)
            issued_refresh = issue_refresh_token(user, request=request, auth_session=session)
            logger.info("Guest login issued.")
            abuse_record_success("LOGIN_IP", request=request, user=user, auth_session=session, account=user.email)
            record_security_event(
                SecurityEvent.EventType.LOGIN_SUCCESS,
                outcome=SecurityEvent.Outcome.SUCCESS,
                severity=SecurityEvent.Severity.INFO,
                reason_code="GUEST_LOGIN",
                user=user,
                auth_session=session,
                request=request,
                metadata={"authentication_method": "guest"},
            )
            return Response({
                "message": "Logged in as guest.",
                "access_token": access_token,
                "refresh_token": issued_refresh.token
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error creating tokens for guest login: {str(e)}")
            return Response({'error': 'Unable to create tokens'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TwoFactorLoginAPIView(APIView):
    """
    Handles the verification of the second factor for users with 2FA enabled.
    """

    def post(self, request):
        """
        Processes a 2FA verification request. Validates the OTP provided by the user against the user's tfa_secret.
        If successful, generates access and refresh tokens.
        """
        data = request.data
        otp = data.get("otp")  # Extract the OTP from the request data
        temp_token = request.COOKIES.get("temp_token")  # Get the temporary token from cookies
        blocked = _first_blocked_abuse_decision([("OTP_IP", {"request": request})])
        if blocked:
            return _abuse_blocked_response(blocked, message="OTP verification temporarily blocked.")

        # Check if both OTP and temporary token are provided
        if not otp or not temp_token:
            abuse_record_failure("OTP_IP", request=request)
            logger.warning("Missing OTP or temporary token")
            record_security_event(
                SecurityEvent.EventType.MFA_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="MISSING_OTP_OR_TEMP_TOKEN",
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            return Response({"error": "OTP and temporary token are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Decode the temporary token to get the user ID
            user_id = decode_temporary_token(temp_token)
            logger.debug(f"Decoded user ID: {user_id}")
        except exceptions.AuthenticationFailed as e:
            abuse_record_failure("OTP_IP", request=request)
            logger.warning(f"Token decoding failed: {str(e)}")
            record_security_event(
                SecurityEvent.EventType.MFA_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="INVALID_TEMP_TOKEN",
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            # Return an error response if the token is invalid or has expired
            return Response({"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Retrieve the user based on the user ID from the temporary token
        try:
            user = get_object_or_404(User, id=user_id)
        except Exception as e:
            logger.error(f"Failed to retrieve user: {str(e)}")
            return Response({"error": "Authentication failed. User not found or 2FA not set up."}, status=status.HTTP_401_UNAUTHORIZED)
            
        if not user or not user.is_2fa_enabled:
            abuse_record_failure("OTP_IP", request=request, user=user, account=getattr(user, "email", None))
            logger.warning("2FA not enabled for this user")
            record_security_event(
                SecurityEvent.EventType.MFA_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="TWO_FACTOR_NOT_ENABLED",
                user=user,
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            return Response({"error": "Authentication failed. User not found or 2FA not set up."}, status=status.HTTP_401_UNAUTHORIZED)
                
        # Verify OTP using the user's 2FA secret
        totp = pyotp.TOTP(user.tfa_secret)
        otp_calls = _otp_abuse_call_args(request=request, user=user)
        blocked = _first_blocked_abuse_decision(otp_calls)
        if blocked:
            return _abuse_blocked_response(blocked, message="OTP verification temporarily blocked.")
        if totp.verify(otp):
            # OTP verification successful; proceed with generating tokens
            logger.debug("OTP verification successful")
            session = create_session(
                user,
                request=request,
                authentication_method="password+totp",
                authentication_strength="mfa",
            )
            access_token = create_access_token(user.id, sid=session.id)
            issued_refresh = issue_refresh_token(user, request=request, auth_session=session)
            logger.debug(f"Refresh token stored in DB for user_id: {user.id}")  
            record_security_event(
                SecurityEvent.EventType.MFA_SUCCESS,
                outcome=SecurityEvent.Outcome.SUCCESS,
                severity=SecurityEvent.Severity.INFO,
                reason_code="OTP_VERIFIED",
                user=user,
                auth_session=session,
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            record_security_event(
                SecurityEvent.EventType.LOGIN_SUCCESS,
                outcome=SecurityEvent.Outcome.SUCCESS,
                severity=SecurityEvent.Severity.INFO,
                reason_code="MFA_LOGIN",
                user=user,
                auth_session=session,
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            for scope, kwargs in otp_calls:
                abuse_record_success(scope, **kwargs)
            
            csrf_token = get_token(request)
            
            response = Response({
                "message": "2FA verification successful",
                "access_token": access_token,
                "refresh_token": issued_refresh.token
            }, status=status.HTTP_200_OK)
            
            # Set the CSRF token as a cookie
            response.set_cookie("csrftoken", csrf_token, httponly=False, secure=True, samesite='Strict')
            return response
        else:
            for scope, kwargs in otp_calls:
                abuse_record_failure(scope, **kwargs)
            logger.warning("Invalid OTP")
            record_security_event(
                SecurityEvent.EventType.MFA_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="INVALID_OTP",
                user=user,
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            raise exceptions.AuthenticationFailed("Authentication failed.")

class GenerateQRCodeAPIView(APIView):
    """
    Generate a QR code for setting up 2FA with an authenticator app.
    """

    def get(self, request, *args, **kwargs):
        user = request.user
        session = resolve_current_auth_session(request)
        require_step_up(
            session,
            STEP_UP_POLICIES["MFA_SETUP"],
            request=request,
            user=user,
            operation="MFA_ENABLE",
            failure_event=SecurityEvent.EventType.STEP_UP_REQUIRED,
        )

        if not user.tfa_secret:
            user.tfa_secret = pyotp.random_base32()
            user.save(update_fields=["tfa_secret"])

        issuer_name = "Gait"
        totp_uri = pyotp.totp.TOTP(user.tfa_secret).provisioning_uri(
            user.email,
            issuer_name=issuer_name,
        )

        qr_img = qrcode.make(totp_uri)
        buf = BytesIO()
        qr_img.save(buf, format="PNG")
        buf.seek(0)

        return HttpResponse(buf.getvalue(), content_type="image/png")


class ChangePasswordAPIView(APIView):
    """Change the authenticated user's password using the current password."""

    def post(self, request):
        user = request.user
        session = resolve_current_auth_session(request)
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")
        new_password_confirm = request.data.get("new_password_confirm")

        if not current_password or not new_password or new_password_confirm is None:
            return Response(
                {"error": "current_password, new_password, and new_password_confirm are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if new_password_confirm is not None and new_password != new_password_confirm:
            return Response(
                {"error": {"new_password_confirm": "Passwords do not match"}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            revoked_count = perform_password_change(
                user=user,
                session=session,
                current_password=current_password,
                new_password=new_password,
                request=request,
            )
        except exceptions.PermissionDenied:
            raise
        except exceptions.ValidationError as exc:
            return Response(
                {"error": exc.detail},
                status=status.HTTP_400_BAD_REQUEST,
            )

        update_session_auth_hash(request, user)
        return Response(
            {
                "message": "Password changed successfully.",
                "sessions_revoked": revoked_count,
            },
            status=status.HTTP_200_OK,
        )


class ReauthenticateAPIView(APIView):
    """Refresh recent-auth state without creating a new session."""

    def post(self, request):
        user = request.user
        session = resolve_current_auth_session(request)
        current_password = request.data.get("current_password")
        otp = request.data.get("otp")

        if not current_password:
            return Response(
                {"error": "current_password is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            session = reauthenticate_session(
                user=user,
                session=session,
                current_password=current_password,
                otp=otp,
                request=request,
            )
        except exceptions.ValidationError as exc:
            return Response(
                {"error": exc.detail},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "message": "Reauthenticated successfully.",
                "recent_auth_at": session.recent_auth_at,
            },
            status=status.HTTP_200_OK,
        )


class ValidateSessionAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        # Check if the request.user is an instance of AnonymousUser
        if isinstance(request.user, AnonymousUser):
            # If so, return a 401 Unauthorized response
            logger.warning("AnonymousUser detected. Authentication credentials were not provided or are invalid.")
            return Response({"detail": "Authentication credentials were not provided or are invalid."}, 
                            status=status.HTTP_401_UNAUTHORIZED)
            
        # Log the authenticated user
        logger.info(f"Authenticated user: {request.user}")
        
        # If the user is authenticated, proceed to serialize and return the user data
        user_data = CustomUserSerializer(request.user).data
        user_data["is_staff"] = bool(request.user.is_staff)
        logger.debug(f"User data: {user_data}")
        response = Response(user_data)
        response["X-CSRFToken"] = get_token(request)
        return response
    
@method_decorator(csrf_exempt, name="dispatch")
class RefreshAPIView(APIView):
    
    def post(self, request):
        # Prefer the Authorization header (explicit, not ambient). Fall back
        # to the request body for clients that transport the refresh token
        # differently -- e.g. Lumen's dev-mode client sends {"refresh": "..."}.
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer"):
            refresh_token = auth_header.split(' ')[1]
        else:
            refresh_token = request.data.get("refresh_token") or request.data.get("refresh")

        if not refresh_token:
            raise exceptions.AuthenticationFailed("Refresh token not found in headers or request body")
        
        rotated = rotate_refresh_token(refresh_token, request=request)

        response = Response({
            "message": "Token refreshed successfully.",
            "access_token": rotated.access_token,
            "refresh_token": rotated.refresh_token,
        }, status=status.HTTP_200_OK)
                
        return response
@method_decorator(csrf_exempt, name='dispatch')        
class LogoutAPIView(APIView):
    def post(self, request):
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer"):
            refresh_token = auth_header.split(' ')[1]
        else:
            refresh_token = (
                request.COOKIES.get("refresh_token")
                or request.data.get("refresh_token")
                or request.data.get("refresh")
            )
        if refresh_token:
            revoke_refresh_token(refresh_token, reason="LOGOUT")
        
        response = Response()
        logout(request)
        response.data = {
            "message": "Signed out"
        }
        logger.info("User signed out and tokens cleared")
        
        return response


@method_decorator(csrf_exempt, name="dispatch")
class LogoutAllAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        user = request.user
        if not user or not user.is_authenticated:
            return Response(
                {"detail": "Authentication credentials were not provided or are invalid."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        revoke_all_sessions(user, reason="LOGOUT_ALL")
        logout(request)
        response = Response({"message": "Signed out of all devices"})
        logger.info("User signed out of all sessions")
        return response


class ForgotPasswordRequestView(APIView):
    """
    API View for handling password reset requests.
    Allows any user (authenticated or not) to request a password reset link.
    """
    permission_classes = [AllowAny]
    def post(self, request):
        reset_message = "If the email is registered with us, you will receive a password reset link shortly."
        """
        Handles POST requests to send password reset emails.

        Expects an email in the POST data and sends a password reset link to it if it's registered in the database.
        The response is intentionally vague to prevent email enumeration attacks.

        Args:
            request (Request): The DRF request object containing POST data.

        Returns:
            Response: DRF Response object with either an error message or a success message.
        """
        email = request.data.get("email")
        if not email:
            # Return an error response if the email field is missing.
            return Response({"error": "Email field is required"}, status=status.HTTP_400_BAD_REQUEST)

        normalized_email = email.strip().lower()
        blocked = _first_blocked_abuse_decision(_password_reset_abuse_call_args(request=request, email=normalized_email))
        if blocked:
            return _abuse_blocked_response(blocked, message="Password reset temporarily blocked.")

        try:
            user = User.objects.get(email=normalized_email)
        except ObjectDoesNotExist:
            abuse_record_failure("PASSWORD_RESET_IP", request=request, account=normalized_email)
            abuse_record_failure("PASSWORD_RESET_ACCOUNT", request=request, account=normalized_email)
            # Do not reveal whether the email address exists to protect user privacy.
            return Response({"message": reset_message}, status=status.HTTP_200_OK)

        # Generate a secure token for the password reset process.
        token = PasswordResetTokenGenerator().make_token(user)

        # Keep only the latest reset record for this email so repeated reset
        # requests remain idempotent and do not collide on the unique token
        # constraint if the password-reset generator returns the same token.
        Reset.objects.filter(email=normalized_email).delete()
        Reset.objects.create(email=normalized_email, token=token)

        # Build the password reset link with the user ID encoded and token.
        react_app_base_url = settings.REACT_APP_BASE_URL
        uid_encoded = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"{react_app_base_url}/reset-password/{uid_encoded}/{token}"

        # Prepare HTML and plain text versions of the password reset email.
        html_content = render_to_string("email/password_reset_email.html", {"reset_link": reset_link})
        text_content = strip_tags(html_content)  # Plain text version for email clients that do not support HTML.

        try:
            subject = "Reset Your Password"
            message = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, [email])
            message.attach_alternative(html_content, "text/html")
            message.send()
            logger.info(f"Password reset email sent to {email}")
            abuse_record_success(["PASSWORD_RESET_IP", "PASSWORD_RESET_ACCOUNT"], request=request, user=user, account=normalized_email)
            record_security_event(
                SecurityEvent.EventType.PASSWORD_RESET_REQUESTED,
                outcome=SecurityEvent.Outcome.SUCCESS,
                severity=SecurityEvent.Severity.INFO,
                reason_code="EMAIL_SENT",
                user=user,
                request=request,
                metadata={"request_recorded": True},
            )
        except Exception as e:
            # Log any failures with sending the email.
            logger.error(f"Failed to send password reset email: {e}")
            # Keep the public response generic so mail-transport failures do not
            # become an account-existence oracle.
            return Response({"message": reset_message}, status=status.HTTP_200_OK)

        # Inform the requester that an email has been sent if applicable.
        return Response({"message": reset_message}, status=status.HTTP_200_OK)
        
class ResetPasswordRequestView(APIView):
    def post(self, request):
        data = request.data
        
        # Data needded from request
        password = data.get("password")
        password_confirm = data.get("password_confirm")
        token = data.get("token")

        # VAlidate required fields
        if not all([password, password_confirm, token]):
            return Response({
                "error": "Password, Password confirmation, and token are required"
            }, status=status.HTTP_400_BAD_REQUEST)

        blocked = _first_blocked_abuse_decision([("PASSWORD_RESET_IP", {"request": request})])
        if blocked:
            return _abuse_blocked_response(blocked, message="Password reset temporarily blocked.")
        
        # Check if passwords match
        if password != password_confirm:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Additional DRF PW validation
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        
        # Retrieve the reset record using the token
        with transaction.atomic():
            logger.info("ResetPasswordRequestView: Attempting to retrieve reset record.")
            reset_password = get_object_or_404(Reset, token=token)
            user = get_object_or_404(User, email=reset_password.email)
            blocked = _first_blocked_abuse_decision(_password_reset_abuse_call_args(request=request, email=user.email))
            if blocked:
                return _abuse_blocked_response(blocked, message="Password reset temporarily blocked.")

            # check_token() verifies the token is both authentic and still
            # within PASSWORD_RESET_TIMEOUT. Without this, a reset link never
            # expires on its own -- the Reset row only ever goes away once used.
            if not PasswordResetTokenGenerator().check_token(user, token):
                abuse_record_failure("PASSWORD_RESET_IP", request=request, account=user.email)
                abuse_record_failure("PASSWORD_RESET_ACCOUNT", request=request, user=user, account=user.email)
                return Response(
                    {"error": "This password reset link is invalid or has expired."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Set the new password and save the user
            user.set_password(password)
            user.save()
            revoked_sessions = revoke_all_sessions(user, reason="PASSWORD_RESET")
            abuse_record_success(["PASSWORD_RESET_IP", "PASSWORD_RESET_ACCOUNT"], request=request, user=user, account=user.email)
        
            # Delete the reset token to prevent reuse
            reset_password.delete()
            record_security_event(
                SecurityEvent.EventType.PASSWORD_RESET_COMPLETED,
                outcome=SecurityEvent.Outcome.SUCCESS,
                severity=SecurityEvent.Severity.INFO,
                reason_code="PASSWORD_RESET",
                user=user,
                request=request,
                metadata={"sessions_revoked": revoked_sessions},
            )
        
        return Response({
            "message": "Password updated"
        }, status=status.HTTP_202_ACCEPTED)

class Toggle2FAAPIView(APIView):
    """Toggle 2FA setup or disablement with explicit security checks."""

    def patch(self, request):
        logger.debug("Toggle2FAAPIView: Received request")
        user = request.user
        session = resolve_current_auth_session(request)
        logger.debug(f"Request user: {user}")

        is_2fa_enabled = request.data.get("is_2fa_enabled")
        if is_2fa_enabled is None:
            logger.error("Missing 'is_2fa_enabled' parameter in request")
            return Response({"error": "Missing 'is_2fa_enabled' parameter. Please specify if two-factor authentication should be enabled or disabled."}, status=status.HTTP_400_BAD_REQUEST)

        if isinstance(is_2fa_enabled, str):
            is_2fa_enabled = is_2fa_enabled.lower() in {"1", "true", "yes", "on"}
        else:
            is_2fa_enabled = bool(is_2fa_enabled)

        if is_2fa_enabled:
            if user.is_2fa_enabled and not user.is_2fa_setup_in_progress:
                record_security_event(
                    SecurityEvent.EventType.MFA_CHANGE_DENIED,
                    outcome=SecurityEvent.Outcome.DENIED,
                    severity=SecurityEvent.Severity.WARNING,
                    reason_code="MFA_ALREADY_ENABLED",
                    user=user,
                    auth_session=session,
                    request=request,
                )
                return Response({"error": "MFA is already enabled."}, status=status.HTTP_400_BAD_REQUEST)
            user.is_2fa_setup_in_progress = True
            user.save(update_fields=["is_2fa_setup_in_progress"])
            logger.info(f"2FA setup initiated for user {user.username}")
        else:
            current_password = request.data.get("current_password")
            otp = request.data.get("otp")
            if not current_password:
                return Response({"error": "current_password is required when disabling MFA."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                revoked_count = perform_mfa_disable(
                    user=user,
                    session=session,
                    current_password=current_password,
                    otp=otp,
                    request=request,
                )
            except exceptions.ValidationError as exc:
                return Response({"error": exc.detail}, status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {
                    "is_2fa_setup_in_progress": user.is_2fa_setup_in_progress,
                    "sessions_revoked": revoked_count,
                },
                status=status.HTTP_200_OK,
            )

        logger.info(
            f"2FA status toggled successfully for user {user.username}. is_2fa_enabled set to {is_2fa_enabled}, is_2fa_setup_in_progress set to {user.is_2fa_setup_in_progress}."
        )

        return Response({
            "is_2fa_setup_in_progress": user.is_2fa_setup_in_progress
        }, status=status.HTTP_200_OK)

class Verify2FASetupAPIView(APIView):
    """Verifies the OTP provided by the user during the initial 2FA setup process."""

    def post(self, request, *args, **kwargs):
        user = request.user
        session = resolve_current_auth_session(request)
        otp_provided = request.data.get("otp")
        otp_calls = _otp_abuse_call_args(request=request, user=user, session=session)

        require_step_up(
            session,
            STEP_UP_POLICIES["MFA_SETUP"],
            request=request,
            user=user,
            operation="MFA_ENABLE",
            failure_event=SecurityEvent.EventType.STEP_UP_REQUIRED,
        )

        blocked = _first_blocked_abuse_decision(otp_calls)
        if blocked:
            return _abuse_blocked_response(blocked, message="OTP verification temporarily blocked.")

        if not user.tfa_secret or not user.is_2fa_setup_in_progress:
            logger.error(f"Attempt to verify OTP without proper 2FA setup by user: {user.username}")
            for scope, kwargs in otp_calls:
                abuse_record_failure(scope, **kwargs)
            record_security_event(
                SecurityEvent.EventType.MFA_FAILURE,
                outcome=SecurityEvent.Outcome.FAILURE,
                severity=SecurityEvent.Severity.WARNING,
                reason_code="TWO_FACTOR_SETUP_NOT_READY",
                user=user,
                auth_session=session,
                request=request,
                metadata={"authentication_method": "password+totp"},
            )
            return Response({"error": {"tfa_setup": "2FA is not set up."}}, status=status.HTTP_400_BAD_REQUEST)

        totp = pyotp.TOTP(user.tfa_secret)
        try:
            with transaction.atomic():
                if totp.verify(otp_provided):
                    user.is_2fa_enabled = True
                    user.is_2fa_setup_in_progress = False
                    user.save(update_fields=["is_2fa_enabled", "is_2fa_setup_in_progress"])

                    old_refresh_token = request.COOKIES.get("refresh_token")
                    if old_refresh_token:
                        revoke_refresh_token(old_refresh_token, reason="MFA_SETUP_COMPLETED")

                    session = create_session(
                        user,
                        request=request,
                        authentication_method="password+totp",
                        authentication_strength="mfa",
                    )
                    new_access_token = create_access_token(user.id, sid=session.id)
                    issued_refresh = issue_refresh_token(user, request=request, auth_session=session)
                    record_security_event(
                        SecurityEvent.EventType.MFA_SUCCESS,
                        outcome=SecurityEvent.Outcome.SUCCESS,
                        severity=SecurityEvent.Severity.INFO,
                        reason_code="OTP_VERIFIED",
                        user=user,
                        auth_session=session,
                        request=request,
                        metadata={"authentication_method": "password+totp"},
                    )
                    record_security_event(
                        SecurityEvent.EventType.MFA_ENABLED,
                        outcome=SecurityEvent.Outcome.SUCCESS,
                        severity=SecurityEvent.Severity.INFO,
                        reason_code="MFA_ENABLED",
                        user=user,
                        auth_session=session,
                        request=request,
                        metadata={"authentication_method": "password+totp"},
                    )
                    for scope, kwargs in otp_calls:
                        abuse_record_success(scope, **kwargs)

                    response = Response({
                        "message": "2FA setup complete, new tokens issued",
                        "access_token": new_access_token,
                        "refresh_token": issued_refresh.token
                    }, status=status.HTTP_200_OK)

                    csrf_token = get_token(request)
                    response.set_cookie("csrftoken", csrf_token, httponly=False, secure=True, samesite="Strict")

                    logger.info(f"2FA setup completed successfully for user: {user.username}")
                    return response
                else:
                    logger.warning(f"Invalid OTP attempt for user: {user.username}")
                    for scope, kwargs in otp_calls:
                        abuse_record_failure(scope, **kwargs)
                    record_security_event(
                        SecurityEvent.EventType.MFA_FAILURE,
                        outcome=SecurityEvent.Outcome.FAILURE,
                        severity=SecurityEvent.Severity.WARNING,
                        reason_code="INVALID_OTP",
                        user=user,
                        auth_session=session,
                        request=request,
                        metadata={"authentication_method": "password+totp"},
                    )
                    return Response({"error": {"otp": "Invalid OTP. Please try again"}}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during 2FA verification for user: {user.username}. Exception: {str(e)}")
            return Response({"error": {"unexpected": "An unexpected error occurred. Please try again later."}}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



        """
        Django CSRF Token Handling (see line 495 - verify2FASetupAPIView)
        get_token(request): This function is part of Django's CSRF protection mechanism.
        When called, it checks for an existing CSRF token associated with the user's session.
        If a token does not exist, it generates a new one. If a token already exists, 
        it will return the existing token.
        
        """
        
@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def whoami_view(request):
    """
    Returns authenticated user details for auth integration.
    """
    user = request.user
    serializer = CustomUserSerializer(user)
    return Response(serializer.data)
