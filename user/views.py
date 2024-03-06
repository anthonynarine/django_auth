import email
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import exceptions

from .models import CustomUser
from .serializers import CustomUserSerializer
from user import serializers


class Register(APIView):
    def post(self, request):
        data = request.data
        
        if data["password"] != data["password_confirm"]:
            raise exceptions.APIException("Passwords do not match!") 
        
        serializer = CustomUserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class Login(APIView):
    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]
        
        user = CustomUser.objects.filter(email=email).first()
        
        if user is None:
            raise exceptions.AuthenticationFailed("Invalid credentials")
        
        if not user.check_password(password):
            raise exceptions.AuthenticationFailed("Invalid Credentials")
        
        serializer = CustomUserSerializer(user)
        
        return Response(serializer.data)
    