import time
import paho.mqtt.client as mqtt
from Speck_Cipher import speckCipher  # Import the speckCipher class

# MQTT Broker details
broker = "192.168.1.14"
port = 1883
topic = "test/speck_topic"
message = "This is a longer message to be encrypted in blocks using the SPECK cipher."

# SPECK encryption parameters
key = 0x1A19181716151413  # 64-bit key
block_size = 32  # Block size in bits
key_size = 64  # Key size in bits

# Initialize the SPECK cipher
cipher = speckCipher(key, block_size, key_size)

# Helper function to pad the message to ensure it's a multiple of the block size
def pad_message(msg, block_size_bytes):
    pad_len = block_size_bytes - (len(msg) % block_size_bytes)
    return msg + (chr(pad_len) * pad_len)

# Convert string message to a list of blocks
def message_to_blocks(message, block_size):
    block_size_bytes = block_size // 8
    padded_message = pad_message(message, block_size_bytes)
    blocks = [padded_message[i:i + block_size_bytes] for i in range(0, len(padded_message), block_size_bytes)]
    return blocks

# Encrypt each block and return a list of encrypted blocks in hexadecimal format
def encrypt_message_blocks(blocks, cipher):
    encrypted_blocks = []
    for block in blocks:
        block_int = int.from_bytes(block.encode(), 'big')  # Convert block to integer
        encrypted_block = cipher.encrypt(block_int)  # Encrypt the block
        encrypted_blocks.append(f"0x{encrypted_block:08x}")  # Convert encrypted block to hex string
    return encrypted_blocks

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected to broker {broker}:{port}")
        
        # Convert the message into blocks
        blocks = message_to_blocks(message, block_size)

        # Encrypt the message block by block
        cipher_text_blocks = encrypt_message_blocks(blocks, cipher)

        # Convert the encrypted blocks into a single string for transmission
        cipher_text_hex = ' '.join(cipher_text_blocks)
        
        # Publish the encrypted message to the topic
        result = client.publish(topic, cipher_text_hex)
        if result[0] == 0:
            print(f"Encrypted message published: {cipher_text_hex}")
        else:
            print("Failed to publish message")
    else:
        print(f"Failed to connect, return code {rc}")

def publish_message():
    # Create MQTT client and connect to the broker
    client = mqtt.Client()

    # Set the connection callback function
    client.on_connect = on_connect

    # Connect to the broker
    client.connect(broker, port, 60)

    # Start the MQTT loop to handle connection
    client.loop_start()

    # Wait for a while to ensure the message is published
    time.sleep(5)

    # Stop the MQTT loop and disconnect
    client.loop_stop()
    client.disconnect()

if __name__ == "__main__":
    publish_message()
