from rest_framework import status
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
    
    EXEMPT_PATHS = [
        '/api/register/',
        '/api/login/',
        '/api/two-factor-login/',
        '/api/forgot-password/',
        '/api/reset-password/',
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.COOKIES.get("accessToken")
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                user_id = payload.get("user_id")
                request.user = User.objects.get(pk=user_id)
            except jwt.ExpiredSignatureError:
                logger.info("Expired token received.")
                return JsonResponse({"error": "Token has expired. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.InvalidTokenError, User.DoesNotExist) as e:
                logger.warning(f"Authentication failure: {e}")
                return JsonResponse({"error": "Invalid token. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            request.user = AnonymousUser()

        response = self.get_response(request)
        return response