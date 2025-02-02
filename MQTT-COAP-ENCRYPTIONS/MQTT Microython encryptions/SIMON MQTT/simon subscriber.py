import paho.mqtt.client as mqtt
from Simon_Cipher import simonCipher  # Import your SIMON cipher implementation
import binascii
import time

# SIMON decryption setup (same key and parameters as the publisher)
key = 0x0f0e0d0c0b0a09080706050403020100  # Key for SIMON-128/128
cipher = simonCipher(key, 128, 128)  # Create an instance of the cipher

# MQTT broker details
broker = "192.168.1.14"
port = 1883
topic = "iot/encrypted"

# Decrypt received message
def decrypt_message(encrypted_bytes):
    # Convert the encrypted bytes to a hex string
    encrypted_hex = binascii.hexlify(encrypted_bytes).decode()

    # Split the encrypted hex string into 64-bit blocks (16 hex digits)
    blocks = [encrypted_hex[i:i+16] for i in range(0, len(encrypted_hex), 16)]

    # Decrypt each block and accumulate the decrypted bytes
    decrypted_bytes = b""
    for block in blocks:
        decrypted_msg = cipher.decrypt(int(block, 16))
        # Convert decrypted block back to hex string
        decrypted_hex = hex(decrypted_msg)[2:]  # Remove '0x' prefix
        
        # Ensure the decrypted_hex has an even number of digits by padding with leading zeros
        if len(decrypted_hex) % 2 != 0:
            decrypted_hex = '0' + decrypted_hex
        
        # Convert hex back to bytes and accumulate
        decrypted_bytes += binascii.unhexlify(decrypted_hex)

    # Attempt to decode the decrypted bytes using UTF-8
    try:
        decrypted_message = decrypted_bytes.decode('utf-8')
        decrypted_message = decrypted_message.rstrip('\x00')  # Strip padding
    except UnicodeDecodeError:
        # If decoding fails, handle the error and return raw hex instead
        print("Warning: Decrypted data is not valid UTF-8. Returning raw hex data.")
        decrypted_message = binascii.hexlify(decrypted_bytes).decode()

    return decrypted_message

# MQTT message callback
def on_message(client, userdata, msg):
    encrypted_message = msg.payload
    print(f"Received encrypted message: {binascii.hexlify(encrypted_message).decode()}")
    
    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message)
    print(f"Decrypted message: {decrypted_message}")

# MQTT connection callback
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected to MQTT broker at {broker}:{port}")
        # Subscribe to the topic
        client.subscribe(topic)
    else:
        print(f"Failed to connect, return code {rc}")

# MQTT setup
client = mqtt.Client()

# Set up connection and message callback
client.on_connect = on_connect
client.on_message = on_message

# Connect to the MQTT broker
client.connect(broker, port, 60)

# Start the network loop in the main thread
client.loop_forever()
