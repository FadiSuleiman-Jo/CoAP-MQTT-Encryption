import json
import paho.mqtt.client as mqtt
from present_encryption import generateRoundKeys, decrypt_ctr

# Define MQTT Broker details
broker = "192.168.1.14"  # Replace with your broker's IP
port = 1883
topic = "test/topic"

# Encryption parameters
key = 0xFFFFFFFFFFFFFFFFFFFF  # 80-bit key for PRESENT cipher
K = generateRoundKeys(key)

# Callback function for when a message is received
def on_message(client, userdata, msg):
    # Decode the received message payload
    data = json.loads(msg.payload.decode())

    # Extract nonce and cipher_texts from the received data
    nonce = data["nonce"]
    cipher_texts = data["cipher_texts"]

    # Decrypt the message using CTR mode
    decrypted_text = decrypt_ctr(cipher_texts, K, nonce)
    print(f"Decrypted message: {decrypted_text}")

# Callback function for connection
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected successfully to broker {broker}:{port}")
        # Subscribe to the topic
        client.subscribe(topic)
    else:
        print(f"Failed to connect, return code {rc}")

# Create an MQTT client instance
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

# Connect to the broker and listen for messages
client.connect(broker, port, 60)
print(f"Subscribed to topic `{topic}`")

# Continuously wait for messages
client.loop_forever()
