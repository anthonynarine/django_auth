# Standard library imports
from datetime import datetime, timedelta
import logging
import random
import string
from urllib import request

# Third-party imports
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import APIView

# Local application/library specific imports
from .auth_token import create_access_token, create_refresh_token, decode_refresh_token, JWTAuthentication
from .models import UserToken, Reset
from .serializers import CustomUserSerializer
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
        data = request.data
        
        password = data.get("password")
        password_confirm = data.get("password_confirm")
        
        # Check if either password is missing
        if password is None or password_confirm is None:
            return Response({"error": "Password and password_confirmation are required "}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if passwords match
        if password != password_confirm:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = CustomUserSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            logger.info(f"{GREEN}New user registered: {user.email}{END}")
        
        return Response(serializer.data)

class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        
        if not email or not password:
            raise exceptions.AuthenticationFailed("Email and password are required")
        
        user = User.objects.filter(email=email).first()
        
        if user is None:
            raise exceptions.AuthenticationFailed("Invalid email")
        
        if not user.check_password(password):
            raise exceptions.AuthenticationFailed("Invalid password")
        
        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id) 
        
        UserToken.objects.create(
            user_id= user.id,
            token= refresh_token,
            expired_at= timezone.now() + timedelta(days=7),
        )
        
        # Loggs for testing
        logger.info(f"{GREEN}Tokens created for user: {user.email}{END}")  
        logger.info(f"{GREEN}{access_token} {user.email}{END}")  
        logger.info(f"{GREEN}{refresh_token} {user.email}{END}")  
        
        response = Response()
        response.set_cookie(
            key="refresh_token", 
            value=refresh_token, 
            httponly=True, 
            secure=True, 
            samesite='Strict'
        )
        response.data = {"access_token": access_token}
        
        return response
    
class UserAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    def get(self, request):
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
    def post(self, request):
        # Generate a random token
        token = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        
        # Retrieve email from the request data
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email field is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create a Reset Instace
        Reset.objects.create(email=email,token=token)
        
        # Dynamically get the domain of the current site
        current_site = get_current_site(request)
        secure_protocol = "https://" if request.is_secure() else "http://"
        url = secure_protocol + current_site.domain + "/reset-password/" + token
        
        # Render the HTML email template
        html_content = render_to_string("email/password_reset_email.html", {"reset_link": url})
        text_content = strip_tags(html_content) # generates a plain text verson of the email for non HTML email clients
        
        email = EmailMultiAlternatives(
            subject="Reset your password",
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email],
        )
        email.attach_alternative(html_content, "text/html") # Attach the HTML version
        try:
            email.send()
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            return Response({
                "error": "Failed to send password reset email"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            "message": "Password reset email sent.", 
        }, status=status.HTTP_200_OK)
        
        
    
