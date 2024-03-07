import jwt
from datetime import datetime, timedelta

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
        "exp": datetime.utcnow() + timedelta(seconds=30),  # Token expiration time (30 seconds from now)
        "iat": datetime.utcnow()  # Token issue time
    }
    # Encoding the payload with a secret key and specifying HS256 as the algorithm
    return jwt.encode(payload, "access_secret", algorithm="HS256")

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
        "exp": datetime.utcnow() + timedelta(days=7),  # Token expiration time (7 days from now)
        "iat": datetime.utcnow()  # Token issue time
    }
    # Encoding the payload with a secret key and specifying HS256 as the algorithm
    return jwt.encode(payload, "access_secret", algorithm="HS256")
