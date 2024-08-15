
import pika

# Connect to RabbitMQ server.
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))

# Create a channel
channel = connection.channel()

# Create a queue on the above channel
channel.queue_declare(queue="hello")

message = "Testing receiver"

# Send message to queue throught the channel
channel.basic_publish(exchange="", routing_key="hello", body=message)
print(" [X] sent 'hello world'")

# close the channel when done
channel.close()

# Close connection
connection.close()

 # to execute in terminal must be in rabbitmq_tutorial dir
 # cmd >>> python send_message.py