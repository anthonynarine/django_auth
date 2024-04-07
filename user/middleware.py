from rest_framework import status
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.urls import resolve
import jwt
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class TokenAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware for JWT token-based user authentication.
    
    This middleware checks for an "accessToken" in the cookies of each incoming request.
    If valid token is found, it decodes the token to retrieve the user's ID, fetches 
    the corresponding user from the database, and attaches it to the request.  If the 
    token is valid, expired, or not present, it sets the request's user to 
    AnonomousUser indicating an unauthenticated or improperly authenticated request.
    
    This middleware effectively decouples authentication logic from your views, making
    your Django application more modular and easier to manage.
    
    Certain endpoints that do not require authentication are exempted from token checks,
    allowing for unrestricted access to those paths. 
    """

    # Paths that have access without authentication
    EXEMPT_PATHS = [
        '/api/register/',
        '/api/login/',
        '/api/two-factor-login/',
        '/api/forgot-password/',
        '/api/reset-password/',
        '/api/token-refresh/',
        '/admin/',
        
    ]

    def __init__(self, get_response):
        """
        Initilize the middleware with the next layer's response callable.
        
        Args:
            get_response: A callable that takes a request and returns a response.   
                            It represents the next layer in the middleware chain, 
                            ultimately concluding with the view if theis is the 
                            last middleware. 
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Process the request throught the middleware.
        
        Check if the request path is exempt from authentication. If not, attempte to 
        authenticate the user using the JWT token found in the request cookies.
        Depending on the token's validity, it either allows the request to proceed 
        to the next layer or returns an immediate JSON response indicationg an error
        
        Args:
            request: HttpRequest object for the current request
        
        returns:
            HttpResponse object for the current request, either from the next layers
            or an error reponse if authentication fails.  
        """
        
        # Normalize the request path to ensure consistency in the path matching
        path = request.path_info.lstrip("/")
        
        # Use Django's resolve() function to match URLs by the name instead of hardcoding paths
        resolved_path_name = resolve(request.path_info).url_name
        # Check if the request path iex exempt from the authentication
        if any(path.startswith(exempt_path.lstrip("/")) for exempt_path in self.EXEMPT_PATHS) or resolved_path_name.startswith('admin:'):
            # Skip the authentication and proceed to the next layer for exempt paths
            return self.get_response(request)

        # Attempt to retrieve the "accessToken" from the reequest cookies
        token = request.COOKIES.get("accessToken")
        if token:
            try:
                # Decode the JWT token to validate and extract user information
                payload = jwt.decode(token, settings.JWT_ACCESS_SECRET, algorithms=["HS256"])
                user_id = payload.get("user_id")
                # Fetch the user from the database and attatch to the request
                request.user = User.objects.get(pk=user_id)
            except jwt.ExpiredSignatureError:
                # Handle expired tokens
                logger.info("Expired token received.")
                return JsonResponse({"error": "Token has expired. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.InvalidTokenError, User.DoesNotExist) as e:
                logger.warning(f"Authentication failure: {e}")
                return JsonResponse({"error": "Invalid token. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            # No token present, treat the request as unauthenticated
            request.user = AnonymousUser()

        # Proceed to the next layer in the middleware chain or to the view. 
        response = self.get_response(request)
        return response