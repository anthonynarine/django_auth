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
    """
    Custom authentication class that handles JWT authentication.

    This class authenticates requests by extracting and validating a JWT from the Authorization header.
    It checks the token's validity, decodes it to extract the user ID, and fetches the corresponding user
    object from the database.

    Attributes:
        None

    Methods:
        authenticate(request): Attempts to authenticate a request based on a JWT in the Authorization header.
    """

    def authenticate(self, request):
        """
        Authenticate the incoming request by checking for a JWT in the 'Authorization' header.

        This method splits the Authorization header to extract the JWT, verifies its validity,
        and attempts to fetch the corresponding user from the database.

        Parameters:
            request (HttpRequest): The HttpRequest object.

        Returns:
            tuple: A tuple of (User, token) if authentication is successful, None otherwise.

        Raises:
            AuthenticationFailed: If the token is expired, invalid, or if the user does not exist.
        """
        auth_header = get_authorization_header(request).decode("utf-8")
        if not auth_header:
            return None

        auth = auth_header.split()
        if auth and len(auth) == 2 and auth[0].lower() == "bearer":
            token = auth[1]
            try:
                user_id = decode_access_token(token)
                user = User.objects.get(pk=user_id)
                logger.info(f"User object accessed for user_id={user_id}")
                return (user, token)
            except jwt.ExpiredSignatureError:
                logger.warning("Token has expired")
                raise exceptions.AuthenticationFailed("Token has expired", code=401)
            except jwt.InvalidTokenError:
                logger.error("Invalid token encountered")
                raise exceptions.AuthenticationFailed("User not found", code=401)
            except User.DoesNotExist:
                logger.error(f"User not found for user_id={user_id}")
                raise exceptions.AuthenticationFailed("User not found", code=401)
            except Exception as e:
                logger.error(f"Authentication Failed: {str(e)}")
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
        "exp": datetime.now(timezone.utc) + timedelta(minutes=20),  # Token expiration time (20 mins from now)
        "iat": datetime.now(timezone.utc)  # Token issue time
    }
    # Encoding the payload with a secret key and specifying HS256 as the algorithm
    return jwt.encode(payload, JWT_ACCESS_SECRET, algorithm="HS256")

def decode_access_token(token):
    try:
        payload = jwt.decode(token, JWT_ACCESS_SECRET, algorithms=["HS256"])
        logger.info(f"{GREEN}Access token validated for user_id={payload['user_id']}{END}")
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        logger.warning(f"{RED}Token has expired{END}")
        raise jwt.ExpiredSignatureError("The token has expired.")
    except jwt.InvalidTokenError as e:
        logger.error(f"{RED}Invalid token encountered: {e}{END}")
        raise jwt.InvalidTokenError("Invalid token.")
    except Exception as e:
        logger.error(f"{RED}Unexpected error decoding token: {str(e)}{END}")
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
    
def create_temporary_2fa_token(user_id):
    """
    Generate a JWT toke for two-factor authentication verfication

    This token is short-lived expiring 10 minutes after issuance. It's used to maintain a secure state between the initial login and completion of the 2fa verifcation. 

    Args:
        user_id: The unique identifier for the user (database ID).

    Returns:
        A JWT temporary token as a string, encoded with HS256 algorithm.
    """
    # Define the expiration time and additional claims for the 2FA process
    expiration = datetime.now(timezone.utc) + timedelta(minutes=10)
    payload = {
        "user_id": user_id, # Unique identifer for the user
        "type": "2FA_temporary", # Specify the type of toke 
        "exp": expiration, # Token expiration time set above
        "iat": datetime.now(timezone.utc), # Token issue time
        "2fa_stage": "awaiting_verification" # Indicate the 2Fa verication is pending
    }
    # Encode the token using the access token's secret (from simplicity)
    token = jwt.encode(payload, JWT_ACCESS_SECRET, algorithm="HS256")
    logger.info(f"{GREEN}Temporary 2FA token issued for user_id={user_id}{END}")
    return token