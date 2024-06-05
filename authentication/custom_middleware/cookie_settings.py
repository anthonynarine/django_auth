from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
import logging

# Retrieve a logger named after the current module for structured logging.
logger = logging.getLogger(__name__)

class CookieSettingsMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        for cookie in response.cookies:
            if cookie in ["access_token", "refresh_token", "temp_token"]:
                # Log current setting before changing
                logger.debug(f"Adjusting setting for cookie: {cookie}")
                logger.debug(f"Original httponly: {response.cookies[cookie]['httponly']}")
                logger.debug(f"Original secure: {response.cookies[cookie]['secure']}")
                logger.debug(f"Original samesite: {response.cookies[cookie]['samesite']}")
                
                # Adjust setting based on DEBUG setting
                response.cookies[cookie]["httponly"] = not settings.DEBUG
                response.cookies[cookie]["secure"] = not settings.DEBUG
                response.cookies[cookie]["samesite"] = "Lax" if settings.DEBUG else "Strict"
                
                # Log new settings after changing
                logger.debug(f"Updated httponly: {response.cookies[cookie]['httponly']}")
                logger.debug(f"Updated secure: {response.cookies[cookie]['secure']}")
                logger.debug(f"Updated samesite: {response.cookies[cookie]['samesite']}")
                
        return response
