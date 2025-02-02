import time
import ubinascii
import gc
import os
import _thread  # For threading in MicroPython
from umqtt.simple import MQTTClient  # MicroPython's MQTT library
from Speck_Cipher import speckCipher  # Import the speckCipher class for encryption

# MQTT Broker details
broker = "192.168.1.14"  # Update with your broker's IP
port = 1883
client_id_pub = "esp32_pub_client"
client_id_sub = "esp32_sub_client"
topic = b"test/speck_topic"
message = "This message is exactly one hundred and twenty-eight characters long. It's used for testing message encryption or transmission length."

# SPECK encryption parameters
key = 0x1A19181716151413  # 64-bit key
block_size = 32  # Block size in bits
key_size = 64  # Key size in bits

# Initialize the SPECK cipher
cipher = speckCipher(key, block_size, key_size)

# Global variable to track transmission start time
transmission_start_time = 0

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
        encrypted_blocks.append(f"{encrypted_block:08x}")  # Convert encrypted block to hex string
    return encrypted_blocks

# Decrypt each block and return the decrypted hexadecimal string
def decrypt_message_blocks(blocks, cipher):
    decrypted_blocks = []
    for block in blocks:
        block_int = int(block, 16)  # Convert the hex string back to integer
        decrypted_block = cipher.decrypt(block_int)  # Decrypt the block
        decrypted_blocks.append(f"{decrypted_block:08x}")  # Convert decrypted block to hex string
    return decrypted_blocks

# Helper function to get storage usage
def get_storage_usage():
    stat = os.statvfs('/')
    total = stat[0] * stat[2]  # Total storage in bytes
    free = stat[0] * stat[3]  # Free storage in bytes
    used = total - free  # Used storage in bytes
    return used, total

# Helper function to measure memory usage
def get_memory_usage():
    gc.collect()  # Run garbage collector to free up memory
    free_mem = gc.mem_free()  # Get free memory in bytes
    allocated_mem = gc.mem_alloc()  # Get allocated memory in bytes
    return allocated_mem, free_mem

# Function to handle MQTT connection and publishing
def publish_thread():
    global transmission_start_time
    time.sleep(5)  # Wait for 5 seconds to allow the subscriber to start first

    try:
        # Create MQTT client instance for publishing
        client = MQTTClient(client_id_pub, broker, port)
        client.connect()
        print(f"Connected to broker {broker}:{port} for publishing")

        # Measure encryption time
        encryption_start = time.ticks_ms()
        
        # Convert the message into blocks and encrypt them
        blocks = message_to_blocks(message, block_size)
        
        # Measure memory before encryption
        mem_before_enc, free_mem_before_enc = get_memory_usage()
        
        cipher_text_blocks = encrypt_message_blocks(blocks, cipher)
        
        encryption_time = time.ticks_diff(time.ticks_ms(), encryption_start)
        print(f"Encryption time: {encryption_time} ms")
        
        # Measure memory after encryption
        mem_after_enc, free_mem_after_enc = get_memory_usage()
        print(f"RAM Usage during encryption: Allocated: {mem_after_enc - mem_before_enc} bytes, Free: {free_mem_before_enc - free_mem_after_enc} bytes")
        
        # Convert the encrypted blocks into a single string for transmission
        cipher_text_hex = ' '.join(cipher_text_blocks)

        # Publish the encrypted message and record the transmission start time
        transmission_start_time = time.ticks_ms()
        client.publish(topic, cipher_text_hex)
        print(f"Published encrypted message: {cipher_text_hex}")

        # Disconnect from the broker
        client.disconnect()

    except OSError as e:
        print(f"Failed to publish message: {e}")

# Function to handle MQTT subscription and receiving messages
def subscribe_thread():
    global transmission_start_time

    def on_message_callback(topic, msg):
        print(f"Received message on topic {topic.decode()}: {msg.decode()}")

        # Measure decryption start time
        decryption_start = time.ticks_ms()

        # Convert received message (hex string) back to a list of blocks
        received_blocks = msg.decode().split()

        # Measure memory before decryption
        mem_before_dec, free_mem_before_dec = get_memory_usage()

        # Decrypt the blocks
        decrypted_blocks = decrypt_message_blocks(received_blocks, cipher)
        decrypted_message_hex = ' '.join(decrypted_blocks)

        decryption_time = time.ticks_diff(time.ticks_ms(), decryption_start)
        print(f"Decryption time: {decryption_time} ms")

        # Measure memory after decryption
        mem_after_dec, free_mem_after_dec = get_memory_usage()
        print(f"RAM Usage during decryption: Allocated: {mem_after_dec - mem_before_dec} bytes, Free: {free_mem_before_dec - free_mem_after_dec} bytes")

        # Print the decrypted message in hex format
        print(f"Decrypted message (hex): {decrypted_message_hex}")

        # Measure transmission time
        transmission_end_time = time.ticks_ms()
        transmission_time = time.ticks_diff(transmission_end_time, transmission_start_time)
        print(f"Transmission time: {transmission_time} ms")

    try:
        # Create MQTT client instance for subscribing
        client = MQTTClient(client_id_sub, broker, port)
        client.set_callback(on_message_callback)
        client.connect()
        print(f"Subscribed to topic {topic.decode()}")

        client.subscribe(topic)

        # Keep listening for messages
        while True:
            client.check_msg()  # Non-blocking check for incoming messages
            time.sleep(1)  # Allow some delay between checks

    except OSError as e:
        print(f"Failed to subscribe: {e}")

# Start the threads for publishing and subscribing
_thread.start_new_thread(subscribe_thread, ())
_thread.start_new_thread(publish_thread, ())

# Keep the main thread alive
while True:
    time.sleep(1)

