from pyexpat import model
from rest_framework.serializers import ModelSerializer
from .models import CustomUser

class CustomUserSerializer(ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "first_name", "last_name", "email", "password"]
        # pw will be inserted into do but retrieve mothod will not return the pw field
        extra_kwargs = {'password': {'write_only': True}} 
        
    def create(self, validated_data):
        # new user is created and with password hashing
        user = CustomUser.objects.create_user(**validated_data)
        return user