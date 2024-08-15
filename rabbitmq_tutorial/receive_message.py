import pika

# Connect to RabbitMQ server
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))

queue_name = "hello"
# Create a channel
channel = connection.channel()

# Create a queue
channel.queue_declare(queue=queue_name)


# Define a callback function to handle incoming messages
def handle_message(channel, method, properties, body):
    print("Recieved Message:", body.decode())


# Set up consumer to receive messages from the queue.
channel.basic_consume(
    queue=queue_name, on_message_callback=handle_message, auto_ack=True
)

# if no messages 
print("waiting for messages")
channel.start_consuming()
