from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
import jwt
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class TokenAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware for token-based authentication.
    
    This middleware checks for an "accessToken" in the cookies of each incoming request.
    If a valid token is found, it decodes the token to retrieve the user's ID and fetches
    the corresponding user from the database, attaching it to the request.
    If the token is invalid or expired, or no token is present, it sets the request's user
    to AnonymousUser, indicating an unauthenticated request.
    """
    
    def __init__(self, get_response):
        """
        Initialize the middleware.
        
        Args:
            get_response: A function to get the response for the current request.
        """
        self.get_response = get_response
        
    def __call__(self, request):
        """
        Process each request through the middleware.
        
        Args:
            request: HttpRequest object for the current request.
        
        Returns:
            HttpResponse object for the current request.
        """
        user = self.get_authenticated_user(request)
        request.user = user if user else AnonymousUser()
        
        # Proceed to the next middleware or view
        response = self.get_response(request)
        return response
    
    def get_authenticated_user(self, request):
        """
        Attempt to authenticate the user based on the JWT token in cookies.
        
        Args:
            request: HttpRequest object for the current request.
            
        Returns:
            The authenticated user object if authentication is successful, otherwise None.
        """
        token = request.COOKIES.get("accessToken")  # Attempt to retrieve the "accessToken"
        if not token:
            return None
        
        try:
            # Decode the JWT token using PyJWT
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = payload.get("user_id")  # Extract the user ID from the token payload
            return User.objects.get(pk=user_id)  # Fetch the user from the database
        except jwt.ExpiredSignatureError:
            # Token has expired
            logger.info("Expired token received.")
            return None  # Return None and handle response in the view
        except jwt.InvalidTokenError as e:
            # Handle any other token errors (e.g., tampering, wrong algorithm)
            logger.warning(f"Invalid token received: {e}")
            return None
        except User.DoesNotExist:
            # Handle the case where no user matches the ID in the token payload
            logger.info("Token contains non-existent user ID.")
            return None
