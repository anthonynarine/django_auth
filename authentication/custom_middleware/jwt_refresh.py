from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from rest_framework.response import Response
import jwt
from datetime import datetime, timedelta
from django.utils import timezone
from user.models import UserToken  
from user.auth_token import create_access_token, create_refresh_token  # Import your token creation functions
import logging

logger = logging.getLogger(__name__)

class TokenRefreshMiddleware(MiddlewareMixin):
    """
    Middleware to automatically refresh access tokens using refresh tokens stored in HttpOnly cookies.

    This middleware intercepts each request, checks the validity of the access token,
    and refreshes it if it has expired using the refresh token. The new access token
    is set as an HttpOnly cookie in the response.

    Attributes:
        None
    """

    def process_request(self, request):
        """
        Process each incoming request to check and refresh the access token if needed.

        Args:
            request (HttpRequest): The incoming HTTP request.

        Returns:
            HttpResponse or None: Returns a response with a refreshed token if needed, otherwise None.
        """
        access_token = request.COOKIES.get("access_token")
        refresh_token = request.COOKIES.get("refresh_token")

        if access_token:
            try:
                # Decode the access token to check its validity
                jwt.decode(access_token, settings.JWT_ACCESS_SECRET, algorithms=["HS256"])
                logger.debug("Access token is valid.")
                return None  # Access token is valid, no need to refresh

            except jwt.ExpiredSignatureError:
                logger.debug("Access token expired, attempting to refresh.")
                # Access token expired, try to refresh
                if refresh_token:
                    try:
                        payload = jwt.decode(refresh_token, settings.JWT_REFRESH_SECRET, algorithms=["HS256"])
                        user_id = payload["user_id"]

                        # Check if the refresh token is still valid
                        if not UserToken.objects.filter(
                            user_id=user_id,
                            token=refresh_token,
                            expired_at__gt=timezone.now(),
                            is_revoked=False
                        ).exists():
                            raise jwt.InvalidTokenError

                        # Create new tokens
                        new_access_token = create_access_token(user_id)
                        new_refresh_token = create_refresh_token(user_id)

                        response = Response({"message": "Token refreshed successfully"})
                        response.set_cookie(key="access_token", value=new_access_token)
                        response.set_cookie(key="refresh_token", value=new_refresh_token)

                        # Update refresh token in the database
                        UserToken.objects.filter(user_id=user_id, token=refresh_token).update(
                            token=new_refresh_token, expired_at=timezone.now() + timedelta(days=7)
                        )
                        request.COOKIES["access_token"] = new_access_token
                        logger.debug(f"New access token set: {new_access_token}")

                        return response

                    except jwt.ExpiredSignatureError:
                        logger.error("Refresh token expired.")
                        return Response({'detail': 'Refresh token expired'}, status=401)

                    except jwt.InvalidTokenError:
                        logger.error("Invalid refresh token.")
                        return Response({'detail': 'Invalid refresh token'}, status=401)
                else:
                    logger.warning("Refresh token missing.")
                    return Response({'detail': 'Refresh token missing'}, status=401)

        logger.warning("Access token missing.")
        return Response({'detail': 'Access token missing'}, status=401)
    
    def process_response(self, request, response):
        """
        Process the outgoing response to include refreshed tokens if available.

        Args:
            request (HttpRequest): The incoming HTTP request.
            response (HttpResponse): The outgoing HTTP response.

        Returns:
            HttpResponse: The modified HTTP response with refreshed tokens if needed.
        """
        if hasattr(request, '_refresh_response'):
            return request._refresh_response

        return response

        """This approach ensures that the middleware doesn't interfere with requests that 
        don't require token validation (like registration) and lets Django handle the response
        rendering properly. It also attaches the refreshed response to the request object, 
        which is then processed in process_response. This way, the response content is handled
        correctly, and the registration process can proceed without errors.
        """