from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
import logging

# Retrieve a logger named after the current module for structured logging.
logger = logging.getLogger(__name__)

class CookieSettingsMiddleware(MiddlewareMixin):
    """
    Middleware to adjust cookie setting based on the Djanog DEBUG setting.
    
    This middleware inpsects the cookies in the response and modifies certain security attributes
    for specific cookies: "access_tokens" "refresh_tokens" and "temp_tokens". The adjustments  are 
    made according to wheater the application is running in develpment (DEBUG=True) or Production (DEBUG=False) mode.
    
    Attributes:
        - httponly: Ensures the cookie is not accessible via Javascript. Set to True in production and False in development
        - secure: Ensures the cookie is only sent over HTTPS. Set to True in production and False in development
    """
    def process_response(self, request, response):
        """
        Adjust cookie setting in the HTTP response based on the DEBUG setting.
        
        For each relevant cookie in the response ("access_token", "refresh_token", "temp_token") this method:
        1. Logs the current setting of each cookie.
        2. Modifies the "httponly", "secure", and "samesite" attributes based on DEBUG setting. 
        3. Logs the updated setting of the cookie
        
        Args:
            request (HttpRequest): The incoming HTTP request. 
            response (HttpResponse): The outgoing HTTP resonose to be modified

        Returns:
            HttpResponse: The modified HTTP response with adjusted cookie setting. 
        """
        for cookie in response.cookies:
            if cookie in ["access_token", "refresh_token", "temp_token"]:
                # Log current setting before changing
                logger.debug(f"Adjusting setting for cookie: {cookie}")
                logger.debug(f"Original httponly: {response.cookies[cookie]['httponly']}")
                logger.debug(f"Original secure: {response.cookies[cookie]['secure']}")
                logger.debug(f"Original samesite: {response.cookies[cookie]['samesite']}")
                
                # Adjust setting based on DEBUG setting
                response.cookies[cookie]["httponly"] = not settings.DEBUG # False in production, True in development
                response.cookies[cookie]["secure"] = not settings.DEBUG   # False in production, True in development
                response.cookies[cookie]["samesite"] = "Lax" if settings.DEBUG else "Strict"
                
                # Log new settings after changing
                logger.debug(f"Updated httponly: {response.cookies[cookie]['httponly']}")
                logger.debug(f"Updated secure: {response.cookies[cookie]['secure']}")
                logger.debug(f"Updated samesite: {response.cookies[cookie]['samesite']}")
                
        return response
