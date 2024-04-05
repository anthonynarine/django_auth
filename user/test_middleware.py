from urllib import response
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from unittest.mock import patch
import jwt
from django.conf import settings
from datetime import datetime, timedelta, timezone

User = get_user_model()


class TokenAuthenticationMiddlewareTest(TestCase):
    
    def setUp(self):
        """
        Set up conditions before running each test.
        
        - Create a test user
        - Generate a valid JWT token for authentication.
        - Patches the jwt.decode function to return the token payload w/o actually decoding
        """
        # It's good practice to call super().setUp()
        super().setup()
        # Create a test user
        self.user = User.objects.create_user(email="naruto@leaf.com", password="ninetails")
        self.client = Client()
        
        # Define a valid payload for the JWT token. This included the user's ID, the token's expiration time and issued time
        self.valid_payload = {
            "user_id": self.user.pk,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),  # Token won't actually expire during test
            "iat": datetime.now(timezone.utc) # issue time
        }
        
        # Encode the playload into a JWT token to be used simulate request w/ valid auth to the middleware. 
        self.valid_token = jwt.encode(self.valid_payload, settings.SECRET_KEY, algorithm="HS256")
                
        # Patch the jwt.decode function to return the payload without actual decoding for the duration of the tests.
        # This approach allows us to simulate the verification of tokens without relying on the jwt library's internal
        # logic, making the tests more focused on our middleware's functionality.
        self.jwt_decode_patch = patch("jwt.decode", return_value=self.valid_payload)
        self.jwt_decode_patch.start()
        
    def tearDown(self):
        """
        Clean up after each test.

        - Stops the patching of the jwt.decode function.
        """
        # Stop the patching of the jwt.decode, restoring it to its original state.
        self.jwt_decode_patch.stop()
        
def test_exempt_path(self):
    """
    Test that the registration endpoint is exempt from token checks and
    successfully registers a user with valid data, including password confirmation.
    """
    # Prepare registration data
    registration_data = {
        "email": "gohan@capsule.corp",
        "first_name": "Son",
        "last_name": "Gohan",
        "password": "beastmode123",
        "password_confirm": "beastmode123"  # Matching password for confirmation
    }

    # Use self.client.post to send a POST request to the registration endpoint
    response = self.client.post(reverse("RegisterAPIView"), registration_data, content_type='application/json')

    # Assert that the response status code is 201 (Created),
    # indicating successful user registration
    self.assertEqual(response.status_code, 201)
    

def

        
        