import paho.mqtt.client as mqtt
from Simon_Cipher import simonCipher  # Import your SIMON cipher implementation
import binascii
import time

# SIMON encryption setup
key = 0x0f0e0d0c0b0a09080706050403020100  # Key for SIMON-128/128
cipher = simonCipher(key, 128, 128)  # Create an instance of the cipher

# MQTT broker details
broker = "192.168.1.14"
port = 1883
topic = "iot/encrypted"

# Pad the last block of the plaintext (to 64 bits)
def pad_block(block, block_size=16):
    # Pad block with '0' to make it exactly 64 bits (8 bytes, 16 hex digits)
    padded_block = block.ljust(block_size, '0')
    return padded_block

# Split plaintext into 64-bit blocks and encrypt each block
def encrypt_message(plaintext):
    # Convert plaintext to hex
    plaintext_hex = binascii.hexlify(plaintext.encode()).decode()

    # Split the hexlified plaintext into 64-bit blocks (16 hex digits = 8 bytes)
    blocks = [plaintext_hex[i:i+16] for i in range(0, len(plaintext_hex), 16)]
    
    # Pad the last block if it is less than 64 bits (16 hex digits)
    if len(blocks[-1]) < 16:
        blocks[-1] = pad_block(blocks[-1])
    
    # Encrypt each block and accumulate the encrypted bytes
    encrypted_bytes = b""
    for block in blocks:
        encrypted_msg = cipher.encrypt(int(block, 16))
        # Convert encrypted block to hex string
        encrypted_hex = hex(encrypted_msg)[2:]  # Remove '0x' from hex string
        
        # Ensure the encrypted_hex has an even number of digits by padding with leading zeros
        if len(encrypted_hex) % 2 != 0:
            encrypted_hex = '0' + encrypted_hex
        
        # Convert the hex string to bytes
        encrypted_bytes += binascii.unhexlify(encrypted_hex)

    return encrypted_bytes

# MQTT connection callback
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected to MQTT broker at {broker}:{port}")
        # Encrypt and publish the message
        plaintext = "This is a test"
        encrypted_message = encrypt_message(plaintext)
        print(f"Publishing encrypted message: {binascii.hexlify(encrypted_message).decode()}")
        client.publish(topic, encrypted_message)
        
        # Allow some time for the message to be sent before disconnecting
        time.sleep(2)
        
        # Disconnect after publishing
        client.disconnect()
    else:
        print(f"Failed to connect, return code {rc}")

# MQTT setup
client = mqtt.Client()

# Set up connection callback
client.on_connect = on_connect

# Connect to the MQTT broker
client.connect(broker, port, 60)

# Start the network loop in a background thread
client.loop_start()

# Allow some time for the connection and publishing process to complete
time.sleep(5)

# Stop the loop and finish
client.loop_stop()
