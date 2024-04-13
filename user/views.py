# Standard library imports
from datetime import timedelta
import datetime
import email
from io import BytesIO
import logging
import os
from urllib import request, response
from decouple import config

# Third-party imports
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.core.validators import validate_email
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMultiAlternatives
from django.forms import ValidationError
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.db import transaction
import jwt
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.shortcuts import get_object_or_404
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import AnonymousUser
from django.middleware.csrf import get_token

import pyotp
import qrcode

# Sendgrid email
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Local application/library specific imports
from .auth_token import JWT_ACCESS_SECRET, create_access_token, create_refresh_token, decode_refresh_token, JWTAuthentication
from .models import TemporarySecurityToken, UserToken, Reset
from .serializers import CustomUserSerializer
from django.http import HttpResponse
from django.conf import settings

User = get_user_model()
print(User)

logger = logging.getLogger(__name__)

# ANSI color codes for logger
RED = '\033[91m'
GREEN = '\033[92m'
END = '\033[0m'


    
class RegisterAPIView(APIView):
    
    def post(self, request):
        """
        Register a new user.

        Validates the provided email, password, and password confirmation.
        Optionally enables 2FA. (currently not in use)
        Sends a thank you email upon successful registration.

        Args:
            request (Request): HTTP POST request containing user registration data.

        Returns:
            Response: HTTP response with user data and status code.
        """
        data = request.data.copy()  # Make a mutable copy of request data

        # Validate and normalize email
        try:
            email = data.get("email", "").strip().lower()
            validate_email(email)
            data["email"] = email
        except ValidationError:
            return Response({"error": "Invalid email format."}, status=status.HTTP_400_BAD_REQUEST)

        # Extract and remove enable_2fa flag from data, if present
        enable_2fa = data.pop('enable_2fa', False)

        # Validation for passwords
        password = data.get("password")
        password_confirm = data.get("password_confirm")
        if not password or not password_confirm:
            return Response({"error": "Password and password confirmation are required."}, status=status.HTTP_400_BAD_REQUEST)
        if password != password_confirm:
            return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        # Initialize the serializer with the modified data
        serializer = CustomUserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
                
                # Send the 2FA setup email
            self.send_thank_you_email(user.email)
                
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def send_thank_you_email(self, email,):
        try:
            
            html_content = render_to_string("email/thank_you_email.html", {})
            text_content = strip_tags(html_content) # generates a plain text verson of the email for non HTML email clients
            
            sg= SendGridAPIClient(config("SENDGRID_API_KEY"))
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = email
            subject = "Thanks you for testing out this application"
            
            content = Mail(
                from_email=from_email,
                to_emails=to_email,
                subject=subject,
                html_content=html_content
            )
            content.plain_text_content = text_content
            
            response = sg.send(content) 
            logger.info(f"Welcome email sent to {to_email}: {response.status_code}")
            logger.info(f"SendGrid response body: {response.body}")  
        except Exception as e:
            logger.error(f"Failed to send welcome email to {email}: {e}", exc_info=True)
        
class LoginAPIView(APIView):
    """
    Handles user login requests. If 2FA is enabled for the user, it requires an additional verification step.
    """
    
    def post(self, request):
        """
        Processes a login request. Validates the user's email and password. If 2FA is enabled for the user,
        responds indicating that a second factor is required.
        """
        data = request.data.copy()
        email = data.get("email", "").strip().lower()  # Normalize email to ensure case-insensitive comparison
        password = data.get("password")
        
        # Validate presence of email and password
        if not email or not password:
            raise exceptions.AuthenticationFailed("Email and password are required")
        
        # Retrieve user by normalized email
        user = User.objects.filter(email=email).first()
        if user is None:
            # For security, use a generic error message
            raise exceptions.AuthenticationFailed("Invalid email or password")
        
        # Validate password
        if not user.check_password(password):
            raise exceptions.AuthenticationFailed("Invalid email or password")
        
        # Check for 2FA
        if user.is_2fa_enabled:
            return Response({
                "message": "2FA required", "2fa_required": True}, status=status.HTTP_206_PARTIAL_CONTENT)
        else:
            # Generate and return tokens for successful login
            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            UserToken.objects.create(user_id=user.id, token=refresh_token, expired_at=timezone.now() + timedelta(days=7))
            
            logger.info(f"Tokens created for user: {user.email}")
            response = Response({"access_token": access_token}, status=status.HTTP_200_OK)
            response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite='Strict')
            
        # Manually set the CSRF token cookie
        csrf_token = get_token(request)
        response.set_cookie("csrftoken", csrf_token, httponly=False, secure=True, samesite="Strict")
    
        return response
    
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
        email = data.get("email", "").strip().lower()  # email normalization
        otp = data.get("otp")
        
        # Retrieve the user and ensure 2FA is set up
        user = User.objects.filter(email=email).first()
        if user is None or not user.tfa_secret:
            raise exceptions.AuthenticationFailed("Authentication failed.")
        
        # Verify OTP
        totp = pyotp.TOTP(user.tfa_secret)
        if totp.verify(otp):
            # OTP verification successful; proceed with generating tokens
            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            UserToken.objects.create(user_id=user.id, token=refresh_token, expired_at=timezone.now() + timedelta(days=7))
            
            response = Response({"access_token": access_token})
            response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="Strict")
            return response
        else:
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
            return Response({"detail": "Authentication credentials were not provided or are invalid."}, 
                            status=status.HTTP_401_UNAUTHORIZED)
        
        # If the user is authenticated, proceed to serialize and return the user data
        return Response(CustomUserSerializer(request.user).data)
    
class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        user_id = decode_refresh_token(refresh_token)
        if not UserToken.objects.filter(
            user=user_id,
            token=refresh_token,
            expired_at__gt=timezone.now()
        ).exists(): 
            raise exceptions.AuthenticationFailed("unauthenticated")
        
        access_token = create_access_token(user_id)
        return Response({
            "access token": access_token
        })
        
class LogoutAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        UserToken.objects.filter(token=refresh_token).delete()
        
        response = Response()
        response.delete_cookie(key="refresh_token")
        response.data = {
            "message": "Signed out"
        }
        
        return response

class ForgotPasswordRequestView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        
        # Retrieve email from the request data
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email field is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response({"message": "If the email is registered with us, you will receive a password reset link shortly."},
                            status=status.HTTP_200_OK)
        # Generate a random token
        token = PasswordResetTokenGenerator().make_token(user)
        
        # Create a Reset Instace
        Reset.objects.create(email=email,token=token)
        
        # Dynamically get the domain of the current site
        react_app_base_url = settings.REACT_APP_BASE_URL
        uid_encoded = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"{react_app_base_url}/reset-password/{uid_encoded}/{token}"
        
        # Render the HTML email template
        html_content = render_to_string("email/password_reset_email.html", {"reset_link": reset_link})
        text_content = strip_tags(html_content) # generates a plain text verson of the email for non HTML email clients
        
        try:
            sg= SendGridAPIClient(config("SENDGRID_API_KEY"))
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = email
            subject = "Reset Your password"
            content = Mail(
                from_email=from_email,
                to_emails=to_email,
                subject=subject,
                html_content=html_content
            )
            response = sg.send(content)
            logger.info(f"Password reset email sent to {to_email}: {response.status_code}")
            logger.info(f"SendGrid response body: {response.body}")  # Additional logging
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            return Response({
                "error": "Failed to send password reset email"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            "message": "Password reset email sent.", 
        }, status=status.HTTP_200_OK)
        
class ResetPasswordRequestView(APIView):
    def post(self, request):
        data = request.data
        
        # Data needded from request
        password = data.get("password")
        password_confirm = data.get("password_confirm")
        token = data.get("token")
        
        # Check any field is missing
        if not all([password, password_confirm, token]):
            return Response({
                "error": "Password, Password confirmation, and token are required"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if passwords match
        if password != password_confirm:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Attempt to retrieve the reset record using the token
        reset_password = Reset.objects.filter(token=token).first() 
        
        if not reset_password:
            raise exceptions.APIException("Invalid link")
        
        user = User.objects.filter(email=reset_password.email).first()
        
        if not user:
            raise exceptions.APIException("User not found")
        
        # Set the new password and save the user
        user.set_password(data['password'])
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
        request.datta: Dictionary containing "is_2fa_enabled" key with the boolean value
        
    Returns:
        Response object with the new state of "is_2fa_enabled" or an error message
    """
    def patch(self, request):
        # Check if the user is authenticated + middleware alread does this but i'll still keep this
        user = request.user
        if not user.is_authenticated:
            return Response ({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        
        is_2fa_enabled = request.data.get("is_2fa_enabled")
        if is_2fa_enabled is None:
            return Response ({"error": "Missing"}, status=status.HTTP_401_UNAUTHORIZED)
        
        user.is_2fa_enabled = is_2fa_enabled  
        user.save(update_fields=["is_2fa_enabled"])
        
        return Response({"is_2fa_enabled": user.is_2fa_enabled})

class Verify2FASetupAPIView(APIView):
    """
    Verifies the OTP provided by the user during the initial 2FA setup process
    """
    @method_decorator(login_required)
    def post(self, request, *args, **kwargs):
        user = request.user
        otp_provided = request.data.get("otp")
        
        if not user.tfa_secret:
            return Response({"error": "2FA is not set up."}, status=status.HTTP_400_BAD_REQUEST)
        
        totp = pyotp.TOTP(user.tfa_secret)
        
        # wrapping the DB operation w/ transaction.atomic(), Django ensures that either all operations within
        # the block are sucessfully committed to the db or none of them are. 
        with transaction.atomic():
            if totp.verify(otp_provided):
                user.is_2fa_enabled = True
                user.save(update_fields=["is_2fa_enabled"])
                return Response({"success": "2FA setup is complete"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid OTP. Please try again"}, status=status.HTTP_400_BAD_REQUEST)


        