# Standard library imports
from datetime import datetime, timedelta, timezone
import logging
import os 


# Third-party imports
from django.contrib.auth import get_user_model
import jwt
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from decouple import config

# Local application/library specific imports
from .serializers import CustomUserSerializer

User = get_user_model()

# Get the JWT secrets using config
JWT_ACCESS_SECRET = config('JWT_ACCESS_SECRET')
JWT_REFRESH_SECRET = config('JWT_REFRESH_SECRET')

logger = logging.getLogger(__name__)
# ANSI color codes for logger
RED = '\033[91m'
GREEN = '\033[92m'
END = '\033[0m'


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = get_authorization_header(request).decode("utf-8")
        auth = auth_header.split()

        if auth and len(auth) == 2 and auth[0].lower() == "bearer":
            token = auth[1]
            try:
                user_id = decode_access_token(token)
                user = User.objects.get(pk=user_id)
                logger.info(f"{GREEN}user object accessed{END}")  
                
                return (user, token)
            
            except jwt.ExpiredSignatureError:
                raise exceptions.AuthenticationFailed("Token has expired", code=401)
            except jwt.InvalidTokenError:
                raise exceptions.AuthenticationFailed("User not Found", code=401)
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed("User not found", code=401)
            except Exception as e:
                raise exceptions.AuthenticationFailed(f"Authentication Failed: {str(e)}")

        return None
        
def create_access_token(user_id):
    """
    Generates a JWT access token for a given user ID.
    
    This access token expires ever 30 seconds after its creation. It's intended for 
    authentication in scenarios that require short-term access and high security.
    
    Args:
        user_id: The unique identifier for the user (typically a database ID).
    
    Returns:
        A JWT access token as a string, encoded with HS256 algorithm.
    """
    # Payload of the token with user_id, expiration time, and issued at time.
    payload = {
        "user_id": user_id,  # Unique identifier for the user
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10),  # Token expiration time (30 seconds from now)
        "iat": datetime.now(timezone.utc)  # Token issue time
    }
    # Encoding the payload with a secret key and specifying HS256 as the algorithm
    return jwt.encode(payload, JWT_ACCESS_SECRET, algorithm="HS256")

def decode_access_token(token):
    try:
        payload = jwt.decode(token, JWT_ACCESS_SECRET, algorithms=["HS256"])

        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError("The token has expired.")
    except jwt.InvalidTokenError:
        raise jwt.InvalidTokenError("Invalid token.")
    except Exception as e:
        # A generic exception for a catch-all unexpected errors;
        raise exceptions.AuthenticationFailed(f"Token cannot be decoded: {str(e)}")


def create_refresh_token(user_id):
    """
    Generates a JWT refresh token for a given user ID.
    
    Unlike access tokens, refresh tokens are long-lived, expiring 7 days after their creation.
    They are used to obtain new access tokens, allowing users to maintain their session without
    needing to re-authenticate.
    
    Args:
        user_id: The unique identifier for the user (typically a database ID).
    
    Returns:
        A JWT refresh token as a string, encoded with HS256 algorithm.
    """
    # Payload of the token with user_id, expiration time (7 days from now), and issued at time.
    payload = {
        "user_id": user_id,  # Unique identifier for the user
        "exp": datetime.now(timezone.utc) + timedelta(days=7),  # Token expiration time (7 days from now)
        "iat": datetime.now(timezone.utc)  # Token issue time
    }
    # Encoding the payload with a secret key and specifying HS256 as the algorithm
    return jwt.encode(payload, JWT_REFRESH_SECRET, algorithm="HS256")


def decode_refresh_token(token):
    logger.info(f"Decoding refresh token: {token}")  
    try:
        payload = jwt.decode(token, JWT_REFRESH_SECRET, algorithms="HS256")
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed("The token has expired.")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid Token Error: {e}")  # Log the error before raising the exception
        raise exceptions.AuthenticationFailed("Invalid token.")
    except Exception as e:
        logger.error(f"Unexpected error decoding token: {e}")  # Log unexpected errors
        raise exceptions.AuthenticationFailed(f"Token cannot be decoded: {str(e)}")
    
    