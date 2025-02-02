import paho.mqtt.client as mqtt
import json
from present_encryption import generateRoundKeys, encrypt_message, pad

# Define the MQTT broker details
broker = "192.168.1.14"  # Replace with your broker's IP
port = 1883
topic = "test/topic"
message = "This message is exactly one hundred and twenty-eight characters long. It's used for testing message encryption or transmission length."

# Encryption parameters
key = 0xFFFFFFFFFFFFFFFFFFFF  # 80-bit key for PRESENT cipher
K = generateRoundKeys(key)

# Pad the message to ensure it's a multiple of the block size (64 bits / 8 bytes)
padded_message = pad(message)

# Encrypt the message block by block, resulting in a list of decimal values
cipher_texts = encrypt_message(padded_message, K)

# Convert the list of encrypted blocks to a JSON string
cipher_text_json = json.dumps(cipher_texts)

# Create an MQTT client instance
client = mqtt.Client()

# Define the callback function for connection
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected successfully to broker {broker}:{port}")
        # Publish the encrypted message in JSON format
        result = client.publish(topic, cipher_text_json)
        status = result[0]
        if status == 0:
            print(f"Published encrypted message to topic `{topic}`: {cipher_text_json}")
        else:
            print(f"Failed to send message to topic `{topic}`")
    else:
        print(f"Failed to connect, return code {rc}")

# Define the callback function for logging if needed
def on_log(client, userdata, level, buf):
    print(f"Log: {buf}")

# Set the on_connect and logging callback functions
client.on_connect = on_connect
client.on_log = on_log  # Optional for debugging purposes

# Connect to the MQTT broker
client.connect(broker, port, 60)

# Start the network loop to process callbacks and ensure messages are sent
client.loop_start()

# Wait a few seconds to ensure the message is published before exiting
import time
time.sleep(5)

# Stop the loop and disconnect from the broker
client.loop_stop()
client.disconnect()
