import json
import pika
import logging
from decouple import config

# Initialize the logger
logger = logging.getLogger(__name__)

def send_user_registered_message(user_data):
    """
    Publish a user registration event to the RabbitMQ 'user_events' exchange.
    
    Args:
        user_data (dict): The user registration data to send as a message.
                        Must include 'id', 'email', 'first_name', and 'last_name'.
    """
    connection = None

    try:
        # Check that the user data contains the required fields
        if not all(key in user_data for key in ("id", "email", "first_name", "last_name")):
            raise ValueError("User data must include 'id', 'email', 'first_name', and 'last_name'.")

        cloudamqp_url = config("CLOUDAMQP_URL", default="").strip()
        if not cloudamqp_url:
            logger.info("CLOUDAMQP_URL is not configured; skipping RabbitMQ publish.")
            return

        # Connect to RabbitMQ server
        connection_params = pika.URLParameters(cloudamqp_url)
        connection = pika.BlockingConnection(connection_params)
        channel = connection.channel()

        # Declare a fanout exchange named 'user_events'
        channel.exchange_declare(exchange="user_events", exchange_type="fanout")
        
        # Convert user data to JSON format
        message = json.dumps(user_data)
        
        # Publish the message to the 'user_events' fanout exchange
        channel.basic_publish(exchange="user_events", routing_key="", body=message)
        
        logger.info(f"Message sent: {message}")
    
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
    
    finally:
        # Ensure the connection is closed
        if connection:
            connection.close()
