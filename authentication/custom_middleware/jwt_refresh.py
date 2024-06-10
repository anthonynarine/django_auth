from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from rest_framework.response import Response
from django.template.response import TemplateResponse
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
    """

    def process_request(self, request):
        """
        Process each incoming request to check and refresh the access token if needed.

        Args:
            request (HttpRequest): The incoming HTTP request.

        Returns:
            None: Let Django handle the response rendering.
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
                        response.set_cookie(key="access_token", value=new_access_token, httponly=True, secure=not settings.DEBUG, samesite='None' if not settings.DEBUG else 'Lax')
                        response.set_cookie(key="refresh_token", value=new_refresh_token, httponly=True, secure=not settings.DEBUG, samesite='None' if not settings.DEBUG else 'Lax')

                        # Update refresh token in the database
                        UserToken.objects.filter(user_id=user_id, token=refresh_token).update(
                            token=new_refresh_token, expired_at=timezone.now() + timedelta(days=7)
                        )
                        request.COOKIES["access_token"] = new_access_token
                        logger.debug(f"New access token set: {new_access_token}")

                        # Attach the refreshed response to the request for later processing
                        request._refresh_response = response
                        return None

                    except jwt.ExpiredSignatureError:
                        logger.error("Refresh token expired.")
                        request._refresh_response = Response({'detail': 'Refresh token expired'}, status=401)
                        return None

                    except jwt.InvalidTokenError:
                        logger.error("Invalid refresh token.")
                        request._refresh_response = Response({'detail': 'Invalid refresh token'}, status=401)
                        return None
                else:
                    logger.warning("Refresh token missing.")
                    request._refresh_response = Response({'detail': 'Refresh token missing'}, status=401)
                    return None

        logger.warning("Access token missing.")
        request._refresh_response = Response({'detail': 'Access token missing'}, status=401)
        return None

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
            logger.debug(f"Returning refreshed response: {request._refresh_response}")
            return request._refresh_response

        # Add new tokens to the response cookies if they exist
        if hasattr(request, '_new_access_token') and hasattr(request, '_new_refresh_token'):
            response.set_cookie(key="access_token", value=request._new_access_token)
            response.set_cookie(key="refresh_token", value=request._new_refresh_token)
        
        # Ensure the TemplateResponse is rendered before modifying it
        if isinstance(response, TemplateResponse):
            response.render()

        logger.debug("Returning original response from view.")
        return response


        """This approach ensures that the middleware doesn't interfere with requests that 
        don't require token validation (like registration) and lets Django handle the response
        rendering properly. It also attaches the refreshed response to the request object, 
        which is then processed in process_response. This way, the response content is handled
        correctly, and the registration process can proceed without errors.
        """