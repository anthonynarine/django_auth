from email.policy import HTTP
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
    """
        Tests for the JWT Authentication Middleware in a Django application.

        This test suite aims to verify the functionality of JWT token-based authentication
        within the application. It tests several key scenarios including:
        - Access to endpoints exempt from authentication (e.g., registration) to ensure they are publicly accessible.
        - Authentication using a valid JWT token and ensuring that the request is authorized.
        - Handling of expired JWT tokens by expecting a 401 Unauthorized response.
        - Handling of invalid JWT tokens by also expecting a 401 Unauthorized response.
        - Access attempts to protected endpoints without providing any JWT token, which should result in a 401 Unauthorized response.

        The tests simulate the presence of JWT tokens in requests both valid and invalid to ensure that the
        middleware correctly identifies authenticated users, denies access when tokens are invalid or expired, 
        and allows access to public endpoints without authentication.
    """
    
    def setUp(self):
        """
        Set up conditions before running each test.
        
        - Create a test user
        - Generate a valid JWT token for authentication.
        - Patches the jwt.decode function to return the token payload w/o actually decoding
        """
        # It's good practice to call super().setUp()
        super().setUp()
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
        if isinstance(self.valid_token, bytes):
            self.valid_token = self.valid_token.decode("utf-8")
                
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
        response = self.client.post(reverse("register"), registration_data, content_type='application/json')

        # Assert that the response status code is 201 (Created),
        # indicating successful user registration
        self.assertEqual(response.status_code, 201)
        

    def test_valid_token(self):
        """
        Test the UserAPIView with a valid JWT token.
        
        Verifies that when a valid JWT is provided in the request's Authorization header,
        the UserAPIView successfully returns a 200 OK status, indicating that the 
        request has been processed and the user is correctly authenticated.
        """
        # Prepare the Authorization header with the valid JWT token
        auth_header = f"Bearer {self.valid_token}"
        # Make a GET request to the "fetch_user" endpoint and capture the response,
        # including the Authorization header in the request
        response = self.client.get(reverse("fetch_user"), HTTP_AUTHORIZATION=auth_header)
        
        # Assert that the response status code is 200 OK
        self.assertEqual(response.status_code, 200)
        
    def test_expired_token(self):
        """
        Test the UserAPIView with an expired JWT token.
        
        Simulate an exported JWT token by patching "jwt.decode" to raise an 
        "ExpiredSignatureError". This test verifies that the API correctly responds
        with a 401 Unauthorized status code, indicating that access is denied to an 
        expired token
        """
        with patch("jwt.decode", side_effect=jwt.ExpiredSignatureError):
            self.client.cookies["accessToken"] = "expired_token"
            response = self.client.get(reverse("fetch_user"))
            self.assertEqual(response.status_code, 401)
            
    def test_invalid_token(self):
        """
        Test the UserAPIView with an invalid JWT token.
        
        This test verifies that the API correctly responds with a 401 Unauthorized status code
        when provided with an invalid JWT token. It simulates an attempt to access the 
        'fetch_user' endpoint with an invalid token, ensuring the application denies access
        as expected in such cases.
        """
        # Set an invalid token in the request's cookies
        self.client.cookies["accessToken"] = "invalid_token"
        # Make a GET request to the 'fetch_user' endpoint
        response = self.client.get(reverse("fetch_user"))
        # Verify that the response is 401 Unauthorized, indicating correct handling of invalid tokens
        self.assertEqual(response.status_code, 401)
        
    def test_no_token(self):
        """
        Test the UserAPIView without any JWT token.
        
        This test verifies that the API correctly responds with a 401 Unauthorized status code
        when no JWT token is provided in the request's cookies. It ensures the application denies
        access as expected in cases where no authentication information is available.
        """
        response = self.client.get(reverse("fetch_user"))
        self.assertEqual(response.status_code, 401)
        
        