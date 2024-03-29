from pyexpat import model
from rest_framework import serializers
from .models import CustomUser

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "first_name", "last_name", "email", "password"]
        # pw will be inserted into do but retrieve mothod will not return the pw field
        extra_kwargs = {'password': {'write_only': True}} 
        
    def create(self, validated_data):
        # new user is created and with password hashing
        user = CustomUser.objects.create_user(**validated_data)
        return user
    
    def validate_password(self, value):
        """
        Check the validity of the password field on its own.
        """
        # Example: Check if password is too short
        if len(value) < 6:
            raise serializers.ValidationError("The password is too short.")
        return value