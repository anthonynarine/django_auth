from django.db import connection
import pika

# Connect to RabbitMQ server
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
channel = connection.channel()

# Declare a direct exchange
channel.exchange_declare(exchange="ultrasound_testing", exchange_type="direct")

# Declare the Queues
channel.queue_declare(queue="vascular_queue")
channel.queue_declare(queue="echo_queue")
channel.queue_declare(queue="general_queue")

# Bind the queues to the exchange with specific routing keys
channel.queue_bind(exchange="ultrasound_testing", queue="vascular_queue", routing_key="vascular")
channel.queue_bind(exchange="ultrasound_testing", queue="echo_queue", routing_key="cardiology")
channel.queue_bind(exchange="ultrasound_testing", queue="general_queue", routing_key="primary_care")

# Define the messages to be sent to each department
vascular_message ="negative for DVT"
cardiology_message = "severe aortic stenosis"
primary_care_message = "anechoic thyroid mass"

# publish messages to the exchange with specificy routing keys
channel.basic_publish(exchange="ultrasound_testing", routing_key="vascular", body=vascular_message )
channel.basic_publish(exchange="ultrasound_testing", routing_key="cardiology", body=cardiology_message )
channel.basic_publish(exchange="ultrasound_testing", routing_key="primary_care", body=primary_care_message )

print ("Messages have been sent to the exchange")

# close the connection
connection.close();

# run python direct_exchange_queue