import time
import ubinascii  # MicroPython equivalent of binascii
import _thread  # MicroPython's threading library
import gc  # Garbage collector for memory usage
import os  # For checking storage usage
from umqtt.simple import MQTTClient  # MicroPython's MQTT library
from Simon_Cipher import simonCipher  # Import your SIMON cipher implementation

# SIMON encryption setup
key = 0x0f0e0d0c0b0a09080706050403020100  # Key for SIMON-128/128
cipher = simonCipher(key, 128, 128)  # Create an instance of the cipher

# MQTT broker details
broker = "192.168.1.14"
port = 1883
topic = b"iot/encrypted"
client_id_pub = "esp32_pub_client"
client_id_sub = "esp32_sub_client"

# Global variable to track transmission start time
transmission_start_time = 0

# Helper function to pad the last block
def pad_block(block, block_size=16):
    padding_needed = block_size - len(block)
    padded_block = block + '0' * padding_needed
    return padded_block

# Helper function to monitor memory usage
def get_memory_usage():
    gc.collect()  # Run garbage collector
    free_mem = gc.mem_free()
    allocated_mem = gc.mem_alloc()
    return allocated_mem, free_mem

# Helper function to monitor storage usage
def get_storage_usage():
    stat = os.statvfs('/')
    total = stat[0] * stat[2]  # Total storage in bytes
    free = stat[0] * stat[3]  # Free storage in bytes
    used = total - free  # Used storage in bytes
    return used, total

# Split plaintext into 64-bit blocks and encrypt each block
def encrypt_message(plaintext):
    plaintext_hex = ubinascii.hexlify(plaintext.encode()).decode()
    blocks = [plaintext_hex[i:i + 16] for i in range(0, len(plaintext_hex), 16)]

    if len(blocks[-1]) < 16:
        blocks[-1] = pad_block(blocks[-1])

    encrypted_bytes = b""
    for block in blocks:
        encrypted_msg = cipher.encrypt(int(block, 16))
        encrypted_hex = hex(encrypted_msg)[2:]
        if len(encrypted_hex) % 2 != 0:
            encrypted_hex = '0' + encrypted_hex
        encrypted_bytes += ubinascii.unhexlify(encrypted_hex)
    return encrypted_bytes

# Decrypt each block and return the decrypted hexadecimal string
def decrypt_message(encrypted_message):
    decrypted_blocks = []
    encrypted_hex = ubinascii.hexlify(encrypted_message).decode()
    blocks = [encrypted_hex[i:i + 16] for i in range(0, len(encrypted_hex), 16)]

    for block in blocks:
        decrypted_msg = cipher.decrypt(int(block, 16))
        decrypted_blocks.append(f"{decrypted_msg:016x}")

    decrypted_message = ' '.join(decrypted_blocks)
    return decrypted_message

# Publisher thread
def publisher_thread():
    global transmission_start_time
    time.sleep(5)  # Wait for 5 seconds to ensure the subscriber starts first

    try:
        # Create MQTT client instance for publishing
        client = MQTTClient(client_id_pub, broker, port)
        client.connect()
        print(f"Publisher connected to broker {broker}:{port}")

        # Monitor memory usage before encryption
        mem_before_enc, free_mem_before_enc = get_memory_usage()

        # Measure encryption time
        encryption_start_time = time.ticks_ms()
        plaintext = "This message is exactly one hundred and twenty-eight characters long. It's used for testing message encryption or transmission length."
        encrypted_message = encrypt_message(plaintext)
        encryption_time = time.ticks_diff(time.ticks_ms(), encryption_start_time)
        print(f"Encryption time: {encryption_time} ms")

        # Monitor memory usage after encryption
        mem_after_enc, free_mem_after_enc = get_memory_usage()
        print(f"RAM during encryption - Allocated: {mem_after_enc - mem_before_enc} bytes, Free: {free_mem_before_enc - free_mem_after_enc} bytes")

        # Get storage usage
        used_storage, total_storage = get_storage_usage()
        print(f"Storage used: {used_storage} bytes / {total_storage} bytes")

        # Track the transmission start time
        transmission_start_time = time.ticks_ms()

        # Publish the encrypted message
        client.publish(topic, encrypted_message)
        print(f"Publisher published encrypted message: {ubinascii.hexlify(encrypted_message).decode()}")

        # Allow some time for the message to be sent before disconnecting
        time.sleep(2)
        client.disconnect()
    
    except OSError as e:
        print(f"Publisher failed to connect or publish: {e}")

# Subscriber thread
def subscriber_thread():
    global transmission_start_time

    def on_message_callback(topic, msg):
        print(f"Subscriber received encrypted message on topic {topic.decode()}: {ubinascii.hexlify(msg).decode()}")

        # Monitor memory usage before decryption
        mem_before_dec, free_mem_before_dec = get_memory_usage()

        # Measure decryption time
        decryption_start_time = time.ticks_ms()
        decrypted_message_hex = decrypt_message(msg)
        decryption_time = time.ticks_diff(time.ticks_ms(), decryption_start_time)
        print(f"Decryption time: {decryption_time} ms")

        # Monitor memory usage after decryption
        mem_after_dec, free_mem_after_dec = get_memory_usage()
        print(f"RAM during decryption - Allocated: {mem_after_dec - mem_before_dec} bytes, Free: {free_mem_before_dec - free_mem_after_dec} bytes")

        # Measure transmission time
        transmission_end_time = time.ticks_ms()
        transmission_time = time.ticks_diff(transmission_end_time, transmission_start_time)
        print(f"Transmission time: {transmission_time} ms")

        print(f"Decrypted message (hex): {decrypted_message_hex}")

    try:
        # Create MQTT client instance for subscribing
        client = MQTTClient(client_id_sub, broker, port)
        client.set_callback(on_message_callback)
        client.connect()
        print(f"Subscriber connected to broker {broker}:{port}")

        client.subscribe(topic)

        # Keep listening for messages
        while True:
            client.check_msg()
            time.sleep(1)  # Small delay betweeFn message checks

    except OSError as e:
        print(f"Subscriber failed to connect or subscribe: {e}")

# Start subscriber and publisher threads
_thread.start_new_thread(subscriber_thread, ())
_thread.start_new_thread(publisher_thread, ())

# Keep the main thread alive
while True:
    time.sleep(1)

