import json
import pika
from decouple import config

def send_user_registered_message(user_data):
    # Connect to RabbitMQ server
    cloudamqp_url = config("CLOUDAMQP_URL")
    connection_params = pika.URLParameters(cloudamqp_url)
    connection = pika.BlockingConnection(connection_params)
    channel = connection.channel()

    # Declate a fanout exchange name "user_events"
    channel.exchange_declare(exchange="user_events", exchange_type="fanout")
    
    # Convert user data to JSON format
    message = json.dumps(user_data)
    
    # Publish the message to the "user_events" fanout exchange
    channel.basic_publish(exchange="user_events", routing_key="", body=message)
    
    print(f" [x] sent {message}")
    
    # Close the connection.  
    