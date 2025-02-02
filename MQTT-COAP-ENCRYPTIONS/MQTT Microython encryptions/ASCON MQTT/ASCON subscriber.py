import paho.mqtt.client as mqtt
from ascon import ascon_decrypt  # Importing from your Ascon module

# Define the MQTT broker details
broker = "192.168.1.14"  # Replace with your broker's IP
port = 1883
topic = "test/topic"

# Encryption parameters (same as used by the publisher)
key = b"thisis16bytekey!"  # 16 bytes key for Ascon-128
nonce = b"unique16bytesstr"  # 16 bytes nonce
associateddata = b""  # No associated data for this example

# Create an MQTT client instance
client = mqtt.Client()

# Define the callback function for connection
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected successfully to broker {broker}:{port}")
        client.subscribe(topic)
    else:
        print(f"Failed to connect, return code {rc}")

# Define the callback function for receiving messages
def on_message(client, userdata, msg):
    print(f"Received encrypted message: {msg.payload}")
    
    # Convert hex string back to bytes and decrypt the message
    ciphertext = bytes.fromhex(msg.payload.decode())
    
    try:
        decrypted_message = ascon_decrypt(key, nonce, associateddata, ciphertext)
        print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
    except Exception as e:
        print(f"Decryption failed: {e}")

# Set the callbacks for connect and message reception
client.on_connect = on_connect
client.on_message = on_message

# Connect to the MQTT broker
client.connect(broker, port, 60)

# Start the network loop to process callbacks and communication
client.loop_forever()  # Keep running to listen for incoming messages
