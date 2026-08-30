# Standard library imports
from datetime import timedelta
from io import BytesIO
import logging
import os

# Third-party imports
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model, authenticate, login, logout
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
from rest_framework.throttling import ScopedRateThrottle

import pyotp
import qrcode

from authentication.settings import ACCESS_TOKEN_SAMESITE, REFRESH_TOKEN_SAMESITE

# Local application/library specific imports
from .auth_token import JWT_ACCESS_SECRET, create_access_token, JWTAuthentication, create_temporary_2fa_token, decode_temporary_token
from .models import CustomUser, UserToken, Reset
from .refresh_tokens import (
    issue_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
)
from .session_services import create_session, revoke_all_sessions
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
    throttle_scope = "login"

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

        # Check if both email and password are provided.
        if not email or not password:
            logger.info("Login attempt failed: Missing email or password.")
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate the user using username and password
        user = authenticate(username=email, password=password)
        if not user:
            # Log and respond if authentication fails
            logger.error("Authentication failed: Invalid email or password.")
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        # Log the user in, which establishes the user's session.
        login(request, user)

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
    throttle_scope = "login"

    def post(self, request):
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

    throttle_scope = "otp_verify"

    def post(self, request):
        """
        Processes a 2FA verification request. Validates the OTP provided by the user against the user's tfa_secret.
        If successful, generates access and refresh tokens.
        """
        data = request.data
        otp = data.get("otp")  # Extract the OTP from the request data
        temp_token = request.COOKIES.get("temp_token")  # Get the temporary token from cookies

        # Check if both OTP and temporary token are provided
        if not otp or not temp_token:
            logger.warning("Missing OTP or temporary token")
            return Response({"error": "OTP and temporary token are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Decode the temporary token to get the user ID
            user_id = decode_temporary_token(temp_token)
            logger.debug(f"Decoded user ID: {user_id}")
        except exceptions.AuthenticationFailed as e:
            logger.warning(f"Token decoding failed: {str(e)}")
            # Return an error response if the token is invalid or has expired
            return Response({"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Retrieve the user based on the user ID from the temporary token
        try:
            user = get_object_or_404(User, id=user_id)
        except Exception as e:
            logger.error(f"Failed to retrieve user: {str(e)}")
            return Response({"error": "Authentication failed. User not found or 2FA not set up."}, status=status.HTTP_401_UNAUTHORIZED)
            
        if not user or not user.is_2fa_enabled:
            logger.warning("2FA not enabled for this user")
            return Response({"error": "Authentication failed. User not found or 2FA not set up."}, status=status.HTTP_401_UNAUTHORIZED)
                
        # Verify OTP using the user's 2FA secret
        totp = pyotp.TOTP(user.tfa_secret)
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
            logger.warning("Invalid OTP")
            raise exceptions.AuthenticationFailed("Authentication failed.")

class GenerateQRCodeAPIView(APIView):
    """
    Generate a QR code for setting up 2FA with an authenticator app
    """
    @method_decorator(login_required)
    def get(self, request, *args, **kwargs):
        user = request.user
        if not user.tfa_secret:
            user.tfa_secret = pyotp.random_base32()
            user.save(update_fields=["tfa_secret"])

        # Construct the providing URI
        issuer_name = "Gait"
        totp_uri = pyotp.totp.TOTP(user.tfa_secret).provisioning_uri(user.email, issuer_name=issuer_name)

        # Generate QR code
        qr_img = qrcode.make(totp_uri)
        
        # Save QR code to a buffer
        buf = BytesIO()
        qr_img.save(buf, format="PNG")
        buf.seek(0)
        
        return HttpResponse(buf.getvalue(), content_type="image/png") 
    
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
        logger.debug(f"User data: {user_data}")
        return Response(CustomUserSerializer(request.user).data)
    
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
    throttle_scope = "password_reset"

    def post(self, request):
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

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            # Do not reveal whether the email address exists to protect user privacy.
            return Response({"message": "If the email is registered with us, you will receive a password reset link shortly."},
                            status=status.HTTP_200_OK)

        # Generate a secure token for the password reset process.
        token = PasswordResetTokenGenerator().make_token(user)

        # Create a reset instance to track this request.
        Reset.objects.create(email=email, token=token)

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
        except Exception as e:
            # Log any failures with sending the email.
            logger.error(f"Failed to send password reset email: {e}")
            return Response({"error": "Failed to send password reset email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Inform the requester that an email has been sent if applicable.
        return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)
        
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

            # check_token() verifies the token is both authentic and still
            # within PASSWORD_RESET_TIMEOUT. Without this, a reset link never
            # expires on its own -- the Reset row only ever goes away once used.
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {"error": "This password reset link is invalid or has expired."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Set the new password and save the user
            user.set_password(password)
            user.save()
            revoke_all_sessions(user, reason="PASSWORD_RESET")
        
            # Delete the reset token to prevent reuse
            reset_password.delete()
        
        return Response({
            "message": "Password updated"
        }, status=status.HTTP_202_ACCEPTED)

class Toggle2FAAPIView(APIView):
    """
    Handles the PATCH request to toggle the "is_2fa_enabled" field of the user.

    This view is responsible for initiating or disabling the two-factor authentication (2FA) setup process.
    When 2FA is enabled, it sets the "is_2fa_setup_in_progress" field to True to indicate that the setup process
    is ongoing. When 2FA is disabled, it resets the "is_2fa_enabled", "is_2fa_setup_in_progress", and "tfa_secret"
    fields to ensure that 2FA is fully disabled.

    Expects:
        request.data: Dictionary containing "is_2fa_enabled" key with a boolean value indicating whether 2FA should be enabled or disabled.

    Returns:
        Response object with the new state of "is_2fa_enabled" and "is_2fa_setup_in_progress", or an error message.
    """
    def patch(self, request):
        logger.debug("Toggle2FAAPIView: Received request")
        user = request.user
        logger.debug(f"Request user: {user}")
        
        # check ensures that only authenticated users can toggle the 2FA status.
        if not user.is_authenticated:
            logger.error("Authentication failed: User is not authenticated")
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        
        is_2fa_enabled = request.data.get("is_2fa_enabled")
        if is_2fa_enabled is None:
            logger.error("Missing 'is_2fa_enabled' parameter in request")
            return Response({"error": "Missing 'is_2fa_enabled' parameter. Please specify if two-factor authentication should be enabled or disabled."}, status=status.HTTP_400_BAD_REQUEST)
        
        # when is_2fa_enabled is True
        if is_2fa_enabled:
            # Start the 2FA setup process
            user.is_2fa_setup_in_progress = True
            logger.info(f"2FA setup initiated for user {user.username}")
        else:
            # Disable 2FA and reset related fields if is_2fa_enabeled is False
            user.is_2fa_enabled = False
            user.is_2fa_setup_in_progress = False
            user.tfa_secret = ""
            logger.info(f"2FA disabled for user {user.username}")
        
        # Save the updated fields to the database
        user.save(update_fields=["is_2fa_enabled", "is_2fa_setup_in_progress", "tfa_secret"])
        
        logger.info(f"2FA status toggled successfully for user {user.username}. is_2fa_enabled set to {is_2fa_enabled}, is_2fa_setup_in_progress set to {user.is_2fa_setup_in_progress}.")
        
        return Response({
            "is_2fa_setup_in_progress": user.is_2fa_setup_in_progress
        }, status=status.HTTP_200_OK)

class Verify2FASetupAPIView(APIView):
    """
    Verifies the OTP provided by the user during the initial 2FA setup process.
    
    This view handles the verification of the one-time password (OTP) during the two-factor authentication (2FA) setup process.
    If the OTP is correct, it finalizes the 2FA setup by enabling 2FA for the user and generates new access, refresh, and CSRF tokens.
    If the OTP is incorrect or the 2FA setup was not initialized properly, it returns an error message.
    
    Methods:
        post(request, *args, **kwargs): Verifies the OTP and completes the 2FA setup process if the OTP is correct.
    """

    throttle_scope = "otp_verify"

    @method_decorator(login_required)
    def post(self, request, *args, **kwargs):
        """
        Handles the POST request to verify the OTP during the 2FA setup process.
        
        Parameters:
            request (HttpRequest): The HTTP request object containing the OTP in the request data.
            
        Returns:
            Response: A Django REST framework response object with either the success message and new tokens
                    if the OTP is correct, or an error message if the OTP is incorrect or the setup was not initialized. 
        """
        # Retrieve the current user
        user = request.user
        
        # Extract the OTP from the request data. This OTP is expected to be provided by the user after scanning their 2FA setup QR code.
        otp_provided = request.data.get("otp")

        # Check if the 2FA secret key is set for the user. This key is necessary to verify the OTP.
        # If it's not set, it means the 2FA setup was not initialized properly, and the verification cannot proceed.
        if not user.tfa_secret or not user.is_2fa_setup_in_progress:
            logger.error(f"Attempt to verify OTP without proper 2FA setup by user: {user.username}")
            return Response({"error": {"tfa_setup": "2FA is not set up."}}, status=status.HTTP_400_BAD_REQUEST)
        
        totp = pyotp.TOTP(user.tfa_secret)
        try:
            with transaction.atomic():
                if totp.verify(otp_provided):
                    user.is_2fa_enabled = True
                    user.is_2fa_setup_in_progress = False
                    user.save(update_fields=["is_2fa_enabled", "is_2fa_setup_in_progress"])
                    
                    # Invalidate old refresh token
                    old_refresh_token = request.COOKIES.get("refresh_token")
                    if old_refresh_token:
                        revoke_refresh_token(old_refresh_token, reason="MFA_SETUP_COMPLETED")
                    
                    # Create new access and refresh tokens
                    session = create_session(
                        user,
                        request=request,
                        authentication_method="password+totp",
                        authentication_strength="mfa",
                    )
                    new_access_token = create_access_token(user.id, sid=session.id)
                    issued_refresh = issue_refresh_token(user, request=request, auth_session=session)
                    
                    # Prepare and send the response with the new tokens
                    response = Response({
                        "message": "2FA setup complete, new tokens issued",
                        "access_token": new_access_token,
                        "refresh_token": issued_refresh.token
                    }, status=status.HTTP_200_OK)
                    
                    # Set CSRF token (this is good security practice)
                    csrf_token = get_token(request)
                    response.set_cookie("csrftoken", csrf_token, httponly=False, secure=True, samesite="Strict")                              
                                        
                    logger.info(f"2FA setup completed successfully for user: {user.username}")
                    return response
                else:
                    logger.warning(f"Invalid OTP attempt for user: {user.username}")
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
