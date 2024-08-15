import csv
import pika
import json

products = []

def read_data():
    """
    Reads data from a CSV file named 'products.csv', 
    appends each row (excluding the header) to a list called 'products', 
    and prints each row as well as the entire list of products.

    The CSV file is expected to have a header row which will be skipped.
    """

    # Open the 'products.csv' file in read mode
    with open("products.csv", "r") as file:  # Make sure the filename is correct
        reader = csv.reader(file)  # Create a CSV reader object
        
        next(reader)  # Skip the header row (name, price, quantity)
        
        # Iterate through each row in the CSV file
        for row in reader:
            products.append(row)  # Append the current row to the 'products' list
            print(f"Reading from csv {row}")  # Print the current row
            
    # Print the entire list of products after reading the CSV file
    print(products)

# Call the function to read the data and print it
if __name__ == "__main__":
    read_data()


# Send products to reabbitma as messages 

# Connect to RabbitMQ server
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))

# Create a channel
channel = connection.channel()

# Create or declare a queue
channel.queue_declare(queue="read_and_send_csv_data")

# Iterate through the products list and publish each product
for product in products:
    # Convert the product list to a string (or JSON)
    product_str = json.dumps(product)  # Serializing the product data to JSON
    channel.basic_publish(exchange="", routing_key="read_and_send_csv_data", body=product_str)
    print(f" [X] Sendint to RabbitMQ server '{product_str}'")

# Close the channel
if not channel.is_closed:
    channel.close()

# Close the connection
if not connection.is_closed:
    connection.close()