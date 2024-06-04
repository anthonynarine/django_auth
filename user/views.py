# Standard library imports
from datetime import timedelta
from io import BytesIO
import logging
import os
 
from decouple import config

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

import pyotp
import qrcode

# Sendgrid email
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from authentication.settings import ACCESS_TOKEN_SAMESITE, REFRESH_TOKEN_SAMESITE

# Local application/library specific imports
from .auth_token import JWT_ACCESS_SECRET, create_access_token, create_refresh_token, decode_refresh_token, JWTAuthentication, create_temporary_2fa_token, decode_temporary_token
from .models import CustomUser, TemporarySecurityToken, UserToken, Reset
from .serializers import CustomUserSerializer
from django.http import HttpResponse
from django.conf import settings

User = get_user_model()
print(User)

logger = logging.getLogger(__name__)
# Test logging
# logger.debug("This is a debug message")
# logger.info("This is an info message")
# logger.warning("This is a warning message")
# logger.error("This is an error message")
# logger.critical("This is a critical message")

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
            
            sg = SendGridAPIClient(config("SENDGRID_API_KEY"))
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = email
            subject = "Thank you for testing out this application"
            
            content = Mail(from_email=from_email, to_emails=to_email, subject=subject, html_content=html_content)
            content.plain_text_content = text_content
            
            response = sg.send(content)
            logger.info(f"Welcome email sent to {to_email}: {response.status_code}")
            logger.info(f"SendGrid response body: {response.body}")
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
        """
        Handle POST request to authenticate a user.

        First, it validates the provided email and password. If authentication is successful,
        it checks whether 2FA is enabled for the user. If 2FA is enabled, it issues a temporary
        token and sets it in an HTTP-only cookie. Otherwise, it issues access and refresh tokens.

        Parameters:
            request (HttpRequest): The request object containing the email and password.

        Returns:
            Response: Django REST Framework response object with either error message and status code
                    or successful login data and tokens.
        """
        logger.info("LoginAPIView: Received request with data: %s", request.data)
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

        # Check if 2FA is enabled for the user
        if user.is_2fa_enabled:
            try:
                # Create a temporary token specifically for 2FA verification
                temp_token = create_temporary_2fa_token(user.id)
                response = Response({'message': '2FA required', '2fa_required': True}, status=status.HTTP_401_UNAUTHORIZED)
                response.set_cookie(
                    "temp_token", temp_token, max_age=600,  # Token expires in 10 minutes
                    httponly=True,  # Cookie is not accessible via JavaScript (helps prevent XSS attacks)
                    secure=not settings.DEBUG,  # when DEBUG is false (is the case for production) secure will = True
                    samesite="Lax"  
                    # Sets the temporary token as a cookie. Only sent over HTTPS in production and allows cross-site requests.
                )
                logger.info(f"2FA required for user {email}. Temporary token issued.")
                return response
            except Exception as e:
                # Handle exceptions related to temporary token creation
                logger.error(f"Failed to create temporary token for user {email}: {str(e)}")
                return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # If 2FA is not enabled, proceed with creating access and refresh tokens
        try:
            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            UserToken.objects.create(
                user_id=user.id,
                token=refresh_token,
                expired_at=timezone.now() + timedelta(days=7)
            )
            response = Response({
                "message": "Logged in successfully."}, status=status.HTTP_200_OK)
            
            # Add debug logs to ensure tokens are being generated correctly
            logger.debug(f"Access Token created: {access_token}")
            logger.debug(f"Refresh Token created: {refresh_token}")
            
            response.set_cookie(
                "access_token", access_token, max_age=9000,
                httponly=True,
                secure=not settings.DEBUG,  # when DEBUG is false (is the case for production) secure will = True
                samesite="Lax"
                # Sets the access token as a cookie. Only sent over HTTPS in production and allows cross-site requests.  
            )
            response.set_cookie(
                "refresh_token", refresh_token, max_age=604800,  # Cookie expires in 7 days
                httponly=True,  # Cookie is not accessible via JavaScript (helps prevent XSS attacks)
                secure=not settings.DEBUG,  # when DEBUG is false (is the case for production) secure will = True
                samesite="Lax"
                # Sets the refresh token as a cookie. Only sent over HTTPS in production and does not allow cross-site requests.
            )
            # Set CSRF token in the cookie for additional security.
            # csrf_token = get_token(request)
            # response.set_cookie("csrftoken", csrf_token, httponly=False, secure=True, samesite="Strict")
            
            logger.info(f"Successful login for {email}. Full access tokens created and sent.")
            return response
        except Exception as e:
            # Handle exceptions related to full access token creation
            logger.error(f"Error creating tokens for user {email}: {str(e)}")
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
        
        # Log the received OTP and temp_token
        logger.debug(f"Received OTP: {otp}")
        logger.debug(f"Received temp_token: {temp_token}")
        
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
        
        #  # Retrieve the user based on the user ID from the temporary token
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
            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            
            logger.debug(f"Access token created: {access_token}")  
            logger.debug(f"Refresh token created: {refresh_token}") 
            
            # Store the refresh token in the database with an expiration date
            UserToken.objects.create(
                user_id=user.id,
                token=refresh_token,
                expired_at=timezone.now() + timedelta(days=7)
            )
            logger.debug(f"Refresh token stored in DB for user_id: {user.id}")  
            
            csrf_token = get_token(request)
            
            # Create the response with the access token
            response = Response({"message": "2FA verification successful"})
            # Set the access token as an HTTP-only cookie
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=not settings.DEBUG,  # when DEBUG is false (is the case for production) secure will = True
                samesite="ACCESS_TOKEN_SAMESITE" 
            )
            # Set the refresh token as an HTTP-only cookie
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=not settings.DEBUG,  # when DEBUG is false (is the case for production) secure will = True
                samesite=REFRESH_TOKEN_SAMESITE
            )
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
        # Log the headers to see if the Authorization header is present
        logger.debug(f"Request headers: {request.headers}")
        
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
        refresh_token = request.COOKIES.get("refresh_token")
        user_id = decode_refresh_token(refresh_token)
        
        # Log the received refresh token and user_id
        logger.debug(f"Received refresh token: {refresh_token}")  
        logger.debug(f"Decoded user ID: {user_id}") 
        
        if not UserToken.objects.filter(
            user=user_id,
            token=refresh_token,
            expired_at__gt=timezone.now()
        ).exists(): 
            raise exceptions.AuthenticationFailed("unauthenticated")
        
        access_token = create_access_token(user_id)
        logger.debug(f"New access token created: {access_token}") 
        
        response = Response({"message": "Token refreshed successfully"})
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=not settings.DEBUG,
            samesite=REFRESH_TOKEN_SAMESITE
        )
        
        return response
@method_decorator(csrf_exempt, name='dispatch')        
class LogoutAPIView(APIView):
    def post(self, request):
        logger.info("LogoutAPIView: Received request with cookies: %s", request.COOKIES)
        refresh_token = request.COOKIES.get("refresh_token")
        UserToken.objects.filter(token=refresh_token).delete()
        
        response = Response()
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        response.delete_cookie(key="csrftoken")
        response.delete_cookie(key="temp_token")
        logout(request)
        response.data = {
            "message": "Signed out"
        }
        logger.info("User signed out and tokens cleared")
        
        return response

class ForgotPasswordRequestView(APIView):
    """
    API View for handling password reset requests.
    Allows any user (authenticated or not) to request a password reset link.
    """
    permission_classes = [AllowAny]

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
            # Setup and send the email through SendGrid.
            sg = SendGridAPIClient(config("SENDGRID_API_KEY"))
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = email
            subject = "Reset Your Password"
            content = Mail(from_email=from_email, to_emails=to_email, subject=subject, html_content=html_content)
            response = sg.send(content)
            # Log the outcome of sending the email.
            logger.info(f"Password reset email sent to {to_email}: {response.status_code}")
            logger.info(f"SendGrid response body: {response.body}")
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
            reset_password = get_object_or_404(Reset, token=token)
            user = get_object_or_404(User, email=reset_password.email) 

            # Set the new password and save the user
            user.set_password(password)
            user.save()
        
            # Delete the reset token to prevent reuse
            reset_password.delete()
        
        return Response({
            "message": "Password updated"
        }, status=status.HTTP_202_ACCEPTED)

class Toggle2FAAPIView(APIView):
    """
    Handles the PATCH request to toggle the "is_2fa_enabled" field of the user
    
    Expects:
        request.data: Dictionary containing "is_2fa_enabled" key with the boolean value
        
    Returns:
        Response object with the new state of "is_2fa_enabled" or an error message
    """
    def patch(self, request):
        logger.debug("Toggle2FAAPIView: Received request")
        # Check if the user is authenticated + middleware already does this but I'll still keep this
        user = request.user
        logger.debug(f"Request user: {user}")
        
        if not user.is_authenticated:
            logger.error("Authentication failed: User is not authenticated")
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        
        is_2fa_enabled = request.data.get("is_2fa_enabled")
        if is_2fa_enabled is None:
            logger.error("Missing 'is_2fa_enabled' parameter in request")
            return Response({"error": "Missing 'is_2fa_enabled' parameter. Please specify if two-factor authentication should be enabled or disabled."}, status=status.HTTP_400_BAD_REQUEST)
        
        user.is_2fa_enabled = is_2fa_enabled  
        user.save(update_fields=["is_2fa_enabled"])
        
        logger.info(f"2FA status toggled successfully for user {user.username}. New value: {is_2fa_enabled}")
        
        return Response({"is_2fa_enabled": user.is_2fa_enabled}, status=status.HTTP_200_OK)
    
class Verify2FASetupAPIView(APIView):
    """
    Verifies the OTP provided by the user during the initial 2FA setup process.
    """
    @method_decorator(login_required)
    def post(self, request, *args, **kwargs):
        # Retrieve the current user
        user = request.user
        
        # Extract the OTP from the request data. This OTP is expected to be provided by the user after scanning their 2FA setup QR code.
        otp_provided = request.data.get("otp")

        # Check if the 2FA secret key is set for the user. This key is necessary to verify the OTP.
        # If it's not set, it means the 2FA setup was not initialized properly, and the verification cannot proceed.
        if not user.tfa_secret:
            logger.error(f"Attempt to verify OTP without 2FA setup by user: {user.username}")
            return Response({"error": {"tfa_setup": "2FA is not set up."}}, status=status.HTTP_400_BAD_REQUEST)
        
        totp = pyotp.TOTP(user.tfa_secret)
        try:
            with transaction.atomic():
                if totp.verify(otp_provided):
                    user.is_2fa_enabled = True
                    user.save(update_fields=["is_2fa_enabled"])
                    
                    # Invalidate old refresh token
                    old_refresh_token = request.COOKIES.get("refresh_token")
                    if old_refresh_token:
                        UserToken.objects.filter(user=user, token=old_refresh_token).delete()
                    
                    # Create new access and refresh tokens
                    # access_token is not sent via Httponly cookie for front end demo using js.cookie
                    new_access_token = create_access_token(user.id)
                    new_refresh_token = create_refresh_token(user.id)
                    UserToken.objects.create(
                        user=user,
                        token=new_refresh_token,
                        expired_at=timezone.now() + timedelta(days=7) 
                    )
                    
                    # Preapte and send the response with the new tokens
                    # TODO send in cookie not in response body
                    response = Response({
                        "message": "2FA setup complete, new tokens issued",
                        "access_token": new_access_token, 
                    }, status=status.HTTP_200_OK)
                    
                    # Set Refresh toke as HttpOnly cookie
            
                    response.set_cookie(
                        "refresh_token", new_refresh_token,
                        httponly=True,
                        secure=True,
                        samesite="Strict")
                    
                    # Set CSRF token (this is good security practice see below for notes on get_token())
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