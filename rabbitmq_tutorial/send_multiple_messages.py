import pika

# Connect to RabbitMQ server
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))

# Create a channel
channel = connection.channel()

# Create a queue
channel.queue_declare(queue="multiple messages")

# Send multiple messages to the queue
messages = ["Hello World", "Second Message", "Third Message", "Another Message", "Final Message"]

for message in messages:
    channel.basic_publish(exchange="", routing_key="multiple messages", body=message)
    print(f" [X] sent '{message}'")

# Close connection
connection.close()

# to execute in terminal must be in rabbitmq_tutorial dir
# cmd >>> python send_multiple_messages.py