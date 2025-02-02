import paho.mqtt.client as mqtt
from Speck_Cipher import speckCipher  # Import the speckCipher class

# MQTT Broker details
broker = "192.168.1.14"
port = 1883
topic = "test/speck_topic"

# SPECK encryption parameters
key = 0x1A19181716151413  # 64-bit key
block_size = 32  # Block size in bits
key_size = 64  # Key size in bits

# Initialize the SPECK cipher
cipher = speckCipher(key, block_size, key_size)

# Helper function to convert a hex string back to integer blocks
def hex_string_to_blocks(hex_string):
    blocks = hex_string.split()  # Split the string by spaces to get individual hex blocks
    int_blocks = [int(block, 16) for block in blocks]  # Convert each block to an integer
    return int_blocks

# Helper function to unpad the decrypted message (assuming PKCS#7 padding)
def unpad_message(padded_message):
    pad_len = padded_message[-1]  # Last byte indicates the number of padding bytes
    return padded_message[:-pad_len]

# Decrypt each block and return the reconstructed message (raw bytes)
def decrypt_message_blocks(encrypted_blocks, cipher):
    decrypted_message = b""  # Using bytes instead of a string
    for block in encrypted_blocks:
        decrypted_block = cipher.decrypt(block)  # Decrypt the block
        decrypted_bytes = decrypted_block.to_bytes(block_size // 8, 'big')  # Convert the decrypted block back to bytes
        decrypted_message += decrypted_bytes  # Append the decrypted bytes to the message
    return decrypted_message

# MQTT message callback for decrypting the message
def on_message(client, userdata, msg):
    encrypted_message_hex = msg.payload.decode()  # Assuming message is sent as a hex string
    print(f"Received encrypted message: {encrypted_message_hex}")

    # Convert hex string to integer blocks
    encrypted_blocks = hex_string_to_blocks(encrypted_message_hex)

    # Decrypt the blocks to reconstruct the original message
    decrypted_message_bytes = decrypt_message_blocks(encrypted_blocks, cipher)

    # Unpad the message to remove padding added during encryption
    decrypted_message_bytes_unpadded = unpad_message(decrypted_message_bytes)


# MQTT connection and subscription
def subscribe_message():
    client = mqtt.Client()

    # Set the message callback function
    client.on_message = on_message

    # Connect to the MQTT broker
    client.connect(broker, port, 60)

    # Subscribe to the topic
    client.subscribe(topic)

    # Start the MQTT loop to continuously check for new messages
    client.loop_forever()

if __name__ == "__main__":
    subscribe_message()
