import json
import pika

def send_user_registered_message(user_data):
    # Connect to RabbitMQ server
    connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
    