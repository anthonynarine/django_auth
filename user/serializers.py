from pyexpat import model
from rest_framework import serializers
from .models import CustomUser

class CustomUserSerializer(serializers.ModelSerializer):
    enable_2fa = serializers.BooleanField(write_only=True, required=False, source="is_2fa_enabled")
    class Meta:
        model = CustomUser
        fields = ["id", "first_name", "last_name", "email", "password", "is_2fa_enabled"]
        # pw will be inserted into do but retrieve mothod will not return the pw field
        extra_kwargs = {'password': {'write_only': True}} 
        
    def create(self, validated_data):
        
        is_2fa_enabled = validated_data.pop("is_2fa_enabled", False)

        # new user is created and with password hashing
        user = CustomUser.objects.create_user(**validated_data, is_2fa_enabled=is_2fa_enabled)
        
        return user
    
    def validate_password(self, value):
        """
        Check the validity of the password field on its own.
        """
        # Example: Check if password is too short
        if len(value) < 6:
            raise serializers.ValidationError("The password is too short.")
        return value