import time
import ubinascii
import _thread  # For threading in MicroPython
import gc  # For memory usage
import os  # For storage usage
from umqtt.simple import MQTTClient
from ascon import ascon_encrypt, ascon_decrypt  # Assuming Ascon is compatible with MicroPython

# Define the MQTT broker details
broker = "0.0.0.0"  # Replace with your broker's IP
port = 1883
publisher_client_id = "esp32_publisher"
subscriber_client_id = "esp32_subscriber"
topic = b"test/topic"
message = "This is exactly thirty-two char."  # Original message

# Encryption parameters
key = b"thisis16bytekey!"  # 16 bytes key for Ascon-128
nonce = b"unique16bytesstr"  # 16 bytes nonce
associateddata = b""  # No associated data for this example

# Global variable to track transmission start time
transmission_start_time = 0

# Function to measure total storage usage
def get_storage_usage():
    stat = os.statvfs('/')
    total_storage = stat[0] * stat[2]  # Total size in bytes
    available_storage = stat[0] * stat[3]  # Available size in bytes
    used_storage = total_storage - available_storage
    return used_storage, total_storage

# Create separate MQTT clients for publishing and subscribing
pub_client = MQTTClient(publisher_client_id, broker, port)
sub_client = MQTTClient(subscriber_client_id, broker, port)

def subscribe_thread():
    global transmission_start_time
    
    def sub_callback(topic, msg):
        print(f"Received encrypted message on topic {topic}: {msg}")

        # Measure decryption start time
        decryption_start = time.ticks_ms()

        # Convert the message from hex string back to bytes
        received_ciphertext = ubinascii.unhexlify(msg)

        # Force garbage collection and measure memory before decryption
        gc.collect()
        mem_free_before = gc.mem_free()
        print(f"Free memory before decryption: {mem_free_before} bytes")

        # Decrypt the received ciphertext
        try:
            decrypted_message = ascon_decrypt(key, nonce, associateddata, received_ciphertext)

            # Measure decryption time
            decryption_time = time.ticks_diff(time.ticks_ms(), decryption_start)
            print(f"Decryption time: {decryption_time} ms")

            # Force garbage collection and measure memory after decryption
            gc.collect()
            mem_free_after = gc.mem_free()
            print(f"Free memory after decryption: {mem_free_after} bytes")

            # Calculate memory used during decryption
            mem_used = mem_free_before - mem_free_after
            print(f"Memory used during decryption: {mem_used} bytes")

            print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
        except Exception as e:
            print(f"Failed to decrypt the message: {e}")

        # Measure transmission time
        transmission_end_time = time.ticks_ms()
        transmission_time = time.ticks_diff(transmission_end_time, transmission_start_time)
        print(f"Transmission time: {transmission_time} ms")

    # Set the callback function for subscribed messages
    sub_client.set_callback(sub_callback)

    try:
        # Connect to the broker and subscribe to the topic
        sub_client.connect()
        print(f"Subscribed to topic '{topic.decode()}'")
        sub_client.subscribe(topic)

        # Listen for messages without blocking the thread
        while True:
            try:
                sub_client.check_msg()  # Non-blocking message check
                time.sleep(1)  # Allow some delay between checks
            except OSError as e:
                print(f"Error during check_msg: {e}")
                break  # Exit loop on error
    except OSError as e:
        print(f"Failed to subscribe or connect: {e}")

def publish_thread():
    global transmission_start_time

    time.sleep(5)  # Wait for 5 seconds

    try:
        # Measure encryption start time
        encryption_start = time.ticks_ms()

        # Force garbage collection and measure memory before encryption
        gc.collect()
        mem_free_before = gc.mem_free()
        print(f"Free memory before encryption: {mem_free_before} bytes")

        # Encrypt the message
        ciphertext = ascon_encrypt(key, nonce, associateddata, message.encode('utf-8'))

        # Measure encryption time
        encryption_time = time.ticks_diff(time.ticks_ms(), encryption_start)
        print(f"Encryption time: {encryption_time} ms")

        # Force garbage collection and measure memory after encryption
        gc.collect()
        mem_free_after = gc.mem_free()
        print(f"Free memory after encryption: {mem_free_after} bytes")

        # Calculate memory used during encryption
        mem_used = mem_free_before - mem_free_after
        print(f"Memory used during encryption: {mem_used} bytes")

        # Get storage usage
        used_storage, total_storage = get_storage_usage()
        print(f"Storage used: {used_storage} bytes, Total storage: {total_storage} bytes")

        # Connect to the MQTT broker
        pub_client.connect()

        # Record the transmission start time
        transmission_start_time = time.ticks_ms()

        # Publish the encrypted message (send as hexadecimal string)
        pub_client.publish(topic, ubinascii.hexlify(ciphertext))  # MQTT sends hex string
        print(ubinascii.hexlify(ciphertext))
        print(f"Published encrypted message to topic '{topic.decode()}' on broker {broker}:{port}")

        # Disconnect after publishing
        pub_client.disconnect()
    except OSError as e:
        print(f"Failed to publish: {e}")

# Start threads
_thread.start_new_thread(subscribe_thread, ())
_thread.start_new_thread(publish_thread, ())

# Keep the main thread alive to allow threads to run
while True:
    time.sleep(1)  # Main thread loop to keep program running

