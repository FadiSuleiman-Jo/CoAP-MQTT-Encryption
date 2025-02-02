import uos  # For storage statistics
from umqtt.simple import MQTTClient  # MicroPython's MQTT library
import struct
import ujson as json  # MicroPython's version of JSON library
import time
import gc  # Garbage collector module
import _thread  # For threading
import binascii  # To convert to/from hex

# Global variables for performance tracking
transmission_start_time = None  # To track when the message was published
transmission_time = None  # Time taken for the message to travel from publisher to subscriber

# ChaCha20 encryption function
def yield_chacha20_xor_stream(key, iv, position=0):
    def rotate(v, c):
        return ((v << c) & 0xffffffff) | v >> (32 - c)

    def quarter_round(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotate(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotate(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotate(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotate(x[b] ^ x[c], 7)

    ctx = [0] * 16
    ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)
    ctx[4:12] = struct.unpack('<8L', key)
    ctx[12] = ctx[13] = position
    ctx[14:16] = struct.unpack('<LL', iv)
    while True:
        x = list(ctx)
        for _ in range(10):
            quarter_round(x, 0, 4, 8, 12)
            quarter_round(x, 1, 5, 9, 13)
            quarter_round(x, 2, 6, 10, 14)
            quarter_round(x, 3, 7, 11, 15)
            quarter_round(x, 0, 5, 10, 15)
            quarter_round(x, 1, 6, 11, 12)
            quarter_round(x, 2, 7, 8, 13)
            quarter_round(x, 3, 4, 9, 14)
        for c in struct.pack('<16L', *(
            (x[i] + ctx[i]) & 0xffffffff for i in range(16))):
            yield c
        ctx[12] = (ctx[12] + 1) & 0xffffffff
        if ctx[12] == 0:
            ctx[13] = (ctx[13] + 1) & 0xffffffff

def chacha20_encrypt(data, key, iv, position=0):
    return bytes(a ^ b for a, b in zip(data, yield_chacha20_xor_stream(key, iv, position)))

def chacha20_decrypt(data, key, iv, position=0):
    return chacha20_encrypt(data, key, iv, position)  # Symmetric encryption/decryption

# Show total storage used on the device
def print_storage_usage():
    statvfs = uos.statvfs('/')
    block_size = statvfs[0]  # Block size
    total_blocks = statvfs[2]  # Total number of blocks
    free_blocks = statvfs[3]  # Number of free blocks
    total_storage = block_size * total_blocks
    used_storage = block_size * (total_blocks - free_blocks)
    print(f"Total storage: {total_storage} bytes, Used storage: {used_storage} bytes")

# MQTT broker details
broker = "192.168.1.14"  # Replace with your broker's IP address
port = 1883
topic = b"iot/sensor"

# Encrypt the message
def encrypt_message(plaintext, key, iv):
    return chacha20_encrypt(plaintext, key, iv)

# Subscriber thread function
def subscriber_thread():
    def sub_callback(topic, msg):
        global transmission_time

        print(f"Message received on topic {topic}: {binascii.hexlify(msg).decode()}")
        
        # Measure transmission time
        transmission_end_time = time.ticks_ms()
        transmission_time = time.ticks_diff(transmission_end_time, transmission_start_time)
        print(f"Transmission time: {transmission_time} ms")

        # Start decryption performance tracking
        key = bytes.fromhex('3f8e12a1b7429df64e8d75f5a36f8b9c2d4d21a7f1b97e68c0d3f5b8cd9a7642')  # 32-byte key
        iv = bytes.fromhex('f5a4b8c2394e8d32')  # 8-byte IV

        gc.collect()
        mem_free_before_decryption = gc.mem_free()
        decryption_start_time = time.ticks_ms()

        decrypted_msg = chacha20_decrypt(msg, key, iv)

        decryption_end_time = time.ticks_ms()
        decryption_time = time.ticks_diff(decryption_end_time, decryption_start_time)
        mem_free_after_decryption = gc.mem_free()
        ram_used_during_decryption = mem_free_before_decryption - mem_free_after_decryption

        print(f"Decrypted message in hex: {binascii.hexlify(decrypted_msg).decode()}")
        print(f"Decryption time: {decryption_time} ms")
        print(f"RAM used during decryption: {ram_used_during_decryption} bytes")

    try:
        client = MQTTClient("esp32_subscriber", broker, port)
        client.set_callback(sub_callback)
        client.connect()
        print(f"Subscriber connected to broker at {broker}:{port} on separate socket")
        client.subscribe(topic)
        while True:
            client.wait_msg()
    except Exception as e:
        print(f"Subscriber failed: {e}")

# Publisher thread function
def publisher_thread():
    global transmission_start_time

    try:
        time.sleep(5)  # Wait for 5 seconds before starting the publisher

        print_storage_usage()

        gc.collect()
        mem_free_before_encryption = gc.mem_free()
        print(f"Free memory before encryption: {mem_free_before_encryption} bytes")

        encryption_start_time = time.ticks_ms()

        message = json.dumps({"This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char"}).encode('utf-8')

        key = bytes.fromhex('3f8e12a1b7429df64e8d75f5a36f8b9c2d4d21a7f1b97e68c0d3f5b8cd9a7642')  # 32-byte key
        iv = bytes.fromhex('f5a4b8c2394e8d32')  # 8-byte IV

        encrypted_message = encrypt_message(message, key, iv)

        encryption_end_time = time.ticks_ms()
        encryption_time_ms = time.ticks_diff(encryption_end_time, encryption_start_time)
        print(f"Time taken to encrypt: {encryption_time_ms} ms")

        gc.collect()
        mem_free_after_encryption = gc.mem_free()
        ram_used_during_encryption = mem_free_before_encryption - mem_free_after_encryption
        print(f"RAM used during encryption: {ram_used_during_encryption} bytes")

        client = MQTTClient("esp32_publisher", broker, port)
        client.connect()
        print(f"Publisher connected to broker at {broker}:{port} on separate socket")

        transmission_start_time = time.ticks_ms()
        print(f"Publishing encrypted message: {binascii.hexlify(encrypted_message).decode()}")
        client.publish(topic, encrypted_message)

        time.sleep(1)
        client.disconnect()

        print_storage_usage()

    except Exception as e:
        print(f"Failed to publish message: {e}")

# Start both threads
try:
    _thread.start_new_thread(subscriber_thread, ())  # Subscriber has its own socket
    _thread.start_new_thread(publisher_thread, ())   # Publisher has its own socket
except Exception as e:
    print(f"Error starting threads: {e}")

# Main loop to keep the script alive
while True:
    time.sleep(1)

