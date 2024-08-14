
import pika

# Connect to RabbitMQ server.
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))

# Create a channel
channel = connection.channel()

# Create a queue
channel.queue_declare(queue="hello")

# Send message to queue
channel.basic_publish(exchange="", routing_key="hello", body="hello world")
print(" [X] sent 'hello world'")

# Close connection
connection.close()

 # to execute in terminal must be in rabbitmq_tutorial dir
 # cmd >>> python send_message.py