import uasyncio as asyncio
from microcoapy import Coap
import gc
from ascon import ascon_decrypt, ascon_encrypt
import time
import uos  # For checking storage

# Global variable to store transmission start time
transmission_start_time = None

# Callback function to handle incoming CoAP response
def response_callback(packet, remoteAddress):
    global transmission_start_time

    print(f"Response from {remoteAddress[0]}:{remoteAddress[1]}")
    print(f"Response Code: {packet.method}")
    print(f"Response Payload: {packet.payload}")

    # Calculate transmission time
    if transmission_start_time:
        transmission_end_time = time.ticks_ms()
        transmission_time_ms = time.ticks_diff(transmission_end_time, transmission_start_time)
        print(f"Transmission time: {transmission_time_ms} ms")
        transmission_start_time = None  # Reset after calculating transmission time

    # Measure memory before decryption
    gc.collect()
    mem_free_before_decryption = gc.mem_free()

    # Attempt to decrypt the response
    key = b"thisis16bytekey!"  # Ascon-128 key
    nonce = b"unique16bytesstr"  # Ascon-128 nonce
    associateddata = b""

    try:
        decryption_start_time = time.ticks_ms()
        decrypted = ascon_decrypt(key, nonce, associateddata, packet.payload)
        decryption_end_time = time.ticks_ms()

        decryption_time_ms = time.ticks_diff(decryption_end_time, decryption_start_time)
        print("Decrypted Response:", decrypted)
        print(f"Decryption time: {decryption_time_ms} ms")

        # Measure memory after decryption
        gc.collect()
        mem_free_after_decryption = gc.mem_free()
        mem_used_during_decryption = mem_free_before_decryption - mem_free_after_decryption
        print(f"Memory used during decryption: {mem_used_during_decryption} bytes")

    except Exception as e:
        print(f"Decryption failed: {e}")

# Receiver thread (task) to establish CoAP connection and wait for incoming messages
async def receiver_task():
    client = Coap()

    try:
        # Start CoAP client on port 5683
        client.responseCallback = response_callback
        client.start(port=5683)  # Using start() with a specific port
        print("Receiver started and waiting for CoAP messages on port 5683...")

        # Poll for incoming messages indefinitely
        while True:
            await asyncio.sleep(1)
            client.poll(timeoutMs=1000)  # Polling every 1 second
    except Exception as e:
        print(f"Receiver task failed: {e}")
    finally:
        client.stop()

# Sender thread (task) to send CoAP messages with a 5-second delay and then every 10 seconds
async def sender_task():
    global transmission_start_time
    await asyncio.sleep(5)  # Initial delay of 5 seconds before sending

    client = Coap()

    # Encrypt the payload using Ascon
    key = b"thisis16bytekey!"  # 16-byte key for Ascon-128
    nonce = b"unique16bytesstr"  # 16-byte nonce
    associateddata = b""
    plaintext = b"This message is exactly one hundred and twenty-eight characters long. It's used for testing message encryption or transmission length."

    try:
        # Start CoAP client on port 9000 for the sender
        client.start(port=9000)  # Using start() with a specific port
        print("Sender started and will send messages every 10 seconds on port 9000...")

        while True:
            gc.collect()
            mem_free_before_encryption = gc.mem_free()
            print(f"Free memory before encryption: {mem_free_before_encryption} bytes")

            # Measure the start time of encryption in milliseconds
            encryption_start_time = time.ticks_ms()
            ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext)
            encryption_end_time = time.ticks_ms()

            encryption_time_ms = time.ticks_diff(encryption_end_time, encryption_start_time)
            print("Encrypted payload:", ciphertext)
            print(f"Time taken to encrypt: {encryption_time_ms} ms")

            gc.collect()
            mem_free_after_encryption = gc.mem_free()
            mem_used_during_encryption = mem_free_before_encryption - mem_free_after_encryption
            print(f"Memory used during encryption: {mem_used_during_encryption} bytes")

            # Set transmission start time
            transmission_start_time = time.ticks_ms()

            # Send POST request to CoAP server
            client.post(
                ip="0.0.0.0",  # Target CoAP server IP
                port=5683,           # Target CoAP server port (Receiver)
                url="iot",           # URL path for the CoAP resource
                payload=ciphertext,  # Encrypted payload to send
                content_format=0      # Set content format (optional)
            )

            await asyncio.sleep(10)  # Send message every 10 seconds
    except Exception as e:
        print(f"Sender task failed: {e}")
    finally:
        client.stop()

# Monitor storage usage
def check_storage():
    stats = uos.statvfs('/')
    total_storage = stats[0] * stats[2]
    free_storage = stats[0] * stats[3]
    used_storage = total_storage - free_storage
    print(f"Total storage: {total_storage} bytes")
    print(f"Used storage: {used_storage} bytes")
    print(f"Free storage: {free_storage} bytes")

# Main function to start both sender and receiver tasks
async def main():
    check_storage()  # Check storage usage
    receiver = asyncio.create_task(receiver_task())
    sender = asyncio.create_task(sender_task())

    await asyncio.gather(receiver, sender)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Error running main: {e}")

