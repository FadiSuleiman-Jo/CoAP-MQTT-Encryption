import paho.mqtt.client as mqtt
from ascon import ascon_encrypt  # Importing from your Ascon module

# Define the MQTT broker details
broker = "192.168.1.14"  # Replace with your broker's IP
port = 1883
topic = "test/topic"
message = "This is a test"  # Original message

# Encryption parameters
key = b"thisis16bytekey!"  # 16 bytes key for Ascon-128
nonce = b"unique16bytesstr"  # 16 bytes nonce
associateddata = b""  # No associated data for this example

# Encrypt the message
ciphertext = ascon_encrypt(key, nonce, associateddata, message.encode('utf-8'))

# Create an MQTT client instance
client = mqtt.Client()

# Define the callback function for connection
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected successfully to broker {broker}:{port}")
    else:
        print(f"Failed to connect, return code {rc}")

# Set the on_connect callback function
client.on_connect = on_connect

# Connect to the MQTT broker
client.connect(broker, port, 60)

# Start the network loop to process callbacks and communication
client.loop_start()

# Publish the encrypted message (send as hexadecimal string)
client.publish(topic, ciphertext.hex())  # MQTT sends hex string
print(ciphertext.hex())
print(f"Published encrypted message to topic '{topic}' on broker {broker}:{port}")

# Stop the loop and disconnect after publishing
client.loop_stop()
client.disconnect()
