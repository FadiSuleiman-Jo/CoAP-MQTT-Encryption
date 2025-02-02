import uasyncio as asyncio
import microcoapy
import time
import gc
import os
from present_module import generateRoundKeys, encrypt_message, decrypt_message

# Global variable to track transmission time
transmission_time = None

# Function to monitor general storage used
def monitor_storage():
    try:
        storage_info = os.statvfs('/')
        total_space = storage_info.f_frsize * storage_info.f_blocks
        free_space = storage_info.f_frsize * storage_info.f_bavail
        used_space = total_space - free_space
        return used_space, total_space
    except:
        return 0, 0  # Fallback for non-compatible environments

# CoAP Client (Receiver)
async def receiver_task():
    client = microcoapy.Coap()

    def response_callback(packet, sender):
        global transmission_time
        print(f"Message received from {sender}: {packet.payload.decode()}")

        # Force garbage collection and track memory before decryption
        gc.collect()
        mem_before_decryption = gc.mem_free()

        # Track decryption time
        start_decryption_time = time.ticks_ms()

        encrypted_payload = [int(x, 16) for x in packet.payload.decode().split()]
        key = 0xFFFFFFFFFFFFFFFFFFFF
        K = generateRoundKeys(key)
        decrypted_message = decrypt_message(encrypted_payload, K)

        # Force garbage collection and track memory after decryption
        gc.collect()
        mem_after_decryption = gc.mem_free()

        decryption_time_ms = time.ticks_diff(time.ticks_ms(), start_decryption_time)
        ram_used_decryption = mem_before_decryption - mem_after_decryption

        print(f"Decrypted message: {decrypted_message}")
        print(f"Decryption time: {decryption_time_ms} ms")
        print(f"RAM used during decryption: {ram_used_decryption} bytes")

        if transmission_time is not None:
            receive_time = time.ticks_ms()
            total_transmission_time = time.ticks_diff(receive_time, transmission_time)
            print(f"Transmission time: {total_transmission_time} ms")

        # Force garbage collection after processing the message
        gc.collect()

    client.responseCallback = response_callback
    client.start(port=5684)  # Receiver port

    while True:
        client.poll(1000)  # Poll every 1 second
        await asyncio.sleep(1)

    client.stop()

# CoAP Client (Sender)
async def sender_task():
    await asyncio.sleep(5)  # Wait 5 seconds before sending

    client = microcoapy.Coap()
    client.start(port=9000)  # Sender port

    while True:
        global transmission_time

        key = 0xFFFFFFFFFFFFFFFFFFFF  # Example key
        K = generateRoundKeys(key)

        # Force garbage collection and track memory before encryption
        gc.collect()
        mem_before_encryption = gc.mem_free()

        # Track encryption time
        start_encryption_time = time.ticks_ms()

        plain_text = "This message is exactly one hundred and twenty-eight characters long. It's used for testing message encryption or transmission length."
        cipher_texts = encrypt_message(plain_text, K)
        encrypted_payload = " ".join(hex(cipher)[2:] for cipher in cipher_texts).encode('utf-8')

        # Force garbage collection and track memory after encryption
        gc.collect()
        mem_after_encryption = gc.mem_free()

        encryption_time_ms = time.ticks_diff(time.ticks_ms(), start_encryption_time)
        ram_used_encryption = mem_before_encryption - mem_after_encryption

        # Set transmission start time
        transmission_time = time.ticks_ms()

        print(f"Sending encrypted message: {encrypted_payload}")
        message_id = client.post("192.168.1.100", 5684, "iot", encrypted_payload)
        print(f"Message Sent. Message ID: {message_id}")

        print(f"Encryption time: {encryption_time_ms} ms")
        print(f"RAM used during encryption: {ram_used_encryption} bytes")

        # Force garbage collection after sending the message
        gc.collect()

        # Monitor general storage
        used_storage, total_storage = monitor_storage()
        print(f"Used storage: {used_storage} bytes / Total storage: {total_storage} bytes")

        await asyncio.sleep(10)  # Send message every 10 seconds

    client.stop()

# Main function to run sender and receiver tasks
async def main():
    receiver = asyncio.create_task(receiver_task())
    sender = asyncio.create_task(sender_task())
    await asyncio.gather(receiver, sender)

if __name__ == "__main__":
    asyncio.run(main())

