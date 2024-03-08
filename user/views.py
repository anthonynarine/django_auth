import email
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header

from .auth_token import create_access_token, create_refresh_token, decode_access_token
from .serializers import CustomUserSerializer
from django.contrib.auth import get_user_model
import logging

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
        
        if data["password"] != data["password_confirm"]:
            raise exceptions.APIException("Passwords do not match!") 
        
        serializer = CustomUserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
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
        
        logger.info(f"{GREEN}Tokens created for user: {user.email}{END}")  
        
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
    def get(self, request):
        auth = get_authorization_header(request).split()

        if auth and len(auth) == 2:
            token = auth[1].decode("utf-8")
            id = decode_access_token(token)

        return Response(auth)
    