import ujson as json  # Use ujson in MicroPython
import time
import _thread
import gc
import os
from umqtt.simple import MQTTClient
from present_encryption import generateRoundKeys, encrypt_ctr, decrypt_ctr, pad

# MQTT Broker details
broker = "192.168.1.14"  # Replace with your broker's IP
port = 1883
subscriber_id = "esp32_subscriber"
publisher_id = "esp32_publisher"
topic = "test/topic"
message = "This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char This is exactly thirty-two char"

# Encryption parameters
key = 0xFFFFFFFFFFFFFFFFFFFF  # 80-bit key for PRESENT cipher
K = generateRoundKeys(key)
nonce = 0x12345678  # Example nonce for CTR mode

# Global variable for transmission time tracking
transmission_start = 0

# Helper function to get current RAM usage
def get_used_ram():
    gc.collect()
    return gc.mem_alloc()

# Define the subscriber thread function
def subscriber_thread():
    def on_message(topic, msg):
        global transmission_start

        # Record the reception time to calculate transmission time
        transmission_time = (time.ticks_ms() - transmission_start)
        print(f"Transmission time: {transmission_time} ms")

        # Decode the received message payload
        data = json.loads(msg.decode())

        # Extract nonce and cipher_texts from the received data
        nonce_received = data["nonce"]
        cipher_texts = data["cipher_texts"]

        # Measure RAM before decryption
        ram_before = get_used_ram()
        decrypt_start = time.ticks_ms()

        # Decrypt the message using CTR mode
        decrypted_text = decrypt_ctr(cipher_texts, K, nonce_received)
        
        # Measure decryption time and RAM after decryption
        decrypt_time = time.ticks_ms() - decrypt_start
        ram_after = get_used_ram()
        print(f"Decryption time: {decrypt_time} ms")
        print(f"RAM used during decryption: {ram_after - ram_before} bytes")

        # Display the decrypted plaintext message
        print(f"Decrypted message (Plaintext): {decrypted_text}")

    # Setup MQTT client for subscriber
    client = MQTTClient(subscriber_id, broker, port)
    client.set_callback(on_message)
    client.connect()
    client.subscribe(topic)
    print("Subscriber connected and waiting for messages...")

    # Continuously wait for messages
    while True:
        client.wait_msg()

# Define the publisher thread function
def publisher_thread():
    global transmission_start

    time.sleep(5)  # Wait for 5 seconds to ensure the subscriber is ready

    # Measure RAM before encryption
    ram_before = get_used_ram()
    encrypt_start = time.ticks_ms()

    # Encrypt the message using CTR mode
    cipher_texts = encrypt_ctr(message, K, nonce)

    # Measure encryption time and RAM after encryption
    encrypt_time = time.ticks_ms() - encrypt_start
    ram_after = get_used_ram()
    print(f"Encryption time: {encrypt_time} ms")
    print(f"RAM used during encryption: {ram_after - ram_before} bytes")

    # Package the nonce and ciphertext together in a JSON string
    payload = json.dumps({
        "nonce": nonce,
        "cipher_texts": cipher_texts
    })

    # Setup MQTT client for publisher
    client = MQTTClient(publisher_id, broker, port)
    client.connect()
    print("Publisher connected, sending encrypted message...")

    # Record the transmission start time
    transmission_start = time.ticks_ms()
    
    # Publish the encrypted message
    client.publish(topic, payload)
    print(f"Published encrypted message to topic `{topic}`: {payload}")

    # Disconnect publisher
    client.disconnect()

    # Check general storage usage
    storage_info = os.statvfs('/')
    total_storage = storage_info[0] * storage_info[2]
    free_storage = storage_info[0] * storage_info[3]
    print(f"Total storage: {total_storage} bytes")
    print(f"Free storage: {free_storage} bytes")
    print(f"Storage used: {total_storage - free_storage} bytes")

# Start the subscriber and publisher threads
_thread.start_new_thread(subscriber_thread, ())
_thread.start_new_thread(publisher_thread, ())

# Keep the main thread active to allow background processing
while True:
    pass

