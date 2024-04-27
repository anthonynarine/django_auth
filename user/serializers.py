
from pyexpat import model
from rest_framework import serializers
from .models import CustomUser

class CustomUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ["id", "first_name", "last_name", "email", "password", "is_2fa_enabled"]
        # pw will be inserted into db but retrieve mothod will not return the pw field
        extra_kwargs = {'password': {'write_only': True}} 
        
    def create(self, validated_data):
        # new user is created and with password hashing
        user = CustomUser.objects.create_user(**validated_data)
        
        return user
    
    def validate_email(self, value):
        """
        Check if the email is already in use.
        """    
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value
    
    def validate_password(self, value):
        """
        Check the validity of the password field on its own.
        """
        # Example: Check if password is too short
        if len(value) < 6:
            raise serializers.ValidationError("The password is too short.")
        return value