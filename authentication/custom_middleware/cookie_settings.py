from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
import logging

# Retrieve a logger named after the current module for structured logging.
logger = logging.getLogger(__name__)

class CookieSettingsMiddleware(MiddlewareMixin):
    """
    Middleware to adjust cookie settings based on the Django DEBUG setting.
    
    This middleware inspects the cookies in the response and modifies certain security attributes
    for specific cookies: "access_token", "refresh_token", and "temp_token". The adjustments are 
    made according to whether the application is running in development (DEBUG=True) or production (DEBUG=False) mode.
    
    Attributes:
        - httponly: Ensures the cookie is not accessible via Javascript. Set to True.
        - secure: Ensures the cookie is only sent over HTTPS. Set to True in production.
        - samesite: Controls if cookies are sent with cross-site requests. Set to 'None'.
        - domain: Sets the domain for the cookie based on the environment.
    """
    def process_response(self, request, response):
        """
        Adjust cookie settings in the HTTP response based on the DEBUG setting.
        
        For each relevant cookie in the response ("access_token", "refresh_token", "temp_token"), this method:
        1. Logs the current setting of each cookie.
        2. Modifies the "httponly", "secure", and "samesite" attributes.
        3. Logs the updated setting of the cookie.
        
        Args:
            request (HttpRequest): The incoming HTTP request.
            response (HttpResponse): The outgoing HTTP response to be modified.
        
        Returns:
            HttpResponse: The modified HTTP response with adjusted cookie settings.
        """
        # Determine the domain based on the enviroment
        domain = "localhoset" if settings.DEBUG else "ant-django-auth-62cf01255868.herokuapp.com"
        for cookie in response.cookies:
            if cookie in ["access_token", "refresh_token", "temp_token"]:
                # Log current settings before changing
                logger.debug(f"Adjusting settings for cookie: {cookie}")
                logger.debug(f"Original httponly: {response.cookies[cookie]['httponly']}")
                logger.debug(f"Original secure: {response.cookies[cookie]['secure']}")
                logger.debug(f"Original samesite: {response.cookies[cookie]['samesite']}")
                logger.debug(f"Original domain: {response.cookies[cookie]['domain']}")
                
                # Adjust settings
                response.cookies[cookie]["httponly"] = False  # Set to False for accessibility in JavaScript
                response.cookies[cookie]["secure"] = not settings.DEBUG  # False in development, True in production
                response.cookies[cookie]["samesite"] = "None"  # Always None for cross-site requests
                response.cookies[cookie]["domain"] = domain  # Set the domain based on the environment
                
                # Log new settings after changing
                logger.debug(f"Updated httponly: {response.cookies[cookie]['httponly']}")
                logger.debug(f"Updated secure: {response.cookies[cookie]['secure']}")
                logger.debug(f"Updated samesite: {response.cookies[cookie]['samesite']}")
                logger.debug(f"Updated domain: {response.cookies[cookie]['domain']}")
                
        return response
