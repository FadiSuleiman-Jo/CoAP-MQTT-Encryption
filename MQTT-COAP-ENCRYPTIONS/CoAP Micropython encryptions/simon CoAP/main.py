import uasyncio as asyncio
import binascii
import uos
import gc
import time
from Simon_Cipher import simonCipher  # Import your SIMON cipher implementation
from microcoapy import Coap  # Import microcoapy library

# SIMON encryption setup
key = 0x0f0e0d0c0b0a09080706050403020100  # 128-bit key
cipher = simonCipher(key, 128, 128)  # SIMON-128/128 setup

# Global variable to track transmission time
transmission_start_time = None

# Helper function to pad the plaintext
def pad_block(plaintext, block_size=16):
    padding_needed = block_size - (len(plaintext) % block_size)
    return plaintext + chr(padding_needed) * padding_needed

# Helper function to remove padding after decryption
def unpad_block(padded_text):
    pad_len = ord(padded_text[-1])
    return padded_text[:-pad_len]

# Monitor memory usage
def monitor_memory():
    gc.collect()  # Run garbage collection
    return gc.mem_alloc(), gc.mem_free()

# Encryption function with performance monitoring
def encrypt_message(plaintext):
    padded_plaintext = pad_block(plaintext)

    # Run GC and monitor memory before encryption
    gc.collect()
    mem_alloc_before, _ = monitor_memory()
    start_time = time.ticks_ms()

    # Encrypt the message
    plaintext_hex = binascii.hexlify(padded_plaintext.encode()).decode()
    blocks = [plaintext_hex[i:i + 32] for i in range(0, len(plaintext_hex), 32)]
    encrypted_bytes = b""

    for block in blocks:
        encrypted_block = cipher.encrypt(int(block, 16))
        encrypted_bytes += binascii.unhexlify(f"{encrypted_block:032x}")

    encryption_time = time.ticks_diff(time.ticks_ms(), start_time)

    # Monitor memory after encryption
    mem_alloc_after, _ = monitor_memory()
    ram_used = mem_alloc_after - mem_alloc_before

    print(f"Encryption time: {encryption_time} ms")
    print(f"RAM used during encryption: {ram_used} bytes")
    return encrypted_bytes

# Decryption function with performance monitoring
def decrypt_message(encrypted_bytes):
    # Run GC and monitor memory before decryption
    gc.collect()
    mem_alloc_before, _ = monitor_memory()
    start_time = time.ticks_ms()

    # Decrypt the message
    decrypted_text = ""
    encrypted_hex = binascii.hexlify(encrypted_bytes).decode()
    blocks = [encrypted_hex[i:i + 32] for i in range(0, len(encrypted_hex), 32)]

    for block in blocks:
        decrypted_block = cipher.decrypt(int(block, 16))
        decrypted_text += binascii.unhexlify(f"{decrypted_block:032x}").decode()

    decrypted_message = unpad_block(decrypted_text)

    decryption_time = time.ticks_diff(time.ticks_ms(), start_time)

    # Monitor memory after decryption
    mem_alloc_after, _ = monitor_memory()
    ram_used = mem_alloc_after - mem_alloc_before

    print(f"Decryption time: {decryption_time} ms")
    print(f"RAM used during decryption: {ram_used} bytes")
    return decrypted_message

# Monitor storage usage
def monitor_storage():
    try:
        stat = uos.statvfs('/')
        total_space = stat[0] * stat[2]
        free_space = stat[0] * stat[3]
        used_space = total_space - free_space
        return used_space, total_space
    except OSError:
        return 0, 0  # Fallback for systems without storage monitoring

# CoAP Receiver Task
async def receiver_task():
    client = Coap()
    client.responseCallback = response_callback
    client.start(port=5684)  # Receiver listens on port 5684

    print("Receiver started on port 5684...")
    while True:
        client.poll(1000)  # Poll for messages every second
        await asyncio.sleep(1)

    client.stop()

# CoAP Sender Task
async def sender_task():
    await asyncio.sleep(5)  # Wait 5 seconds before starting the sender

    client = Coap()
    client.start(port=9000)  # Sender uses port 9000

    while True:
        global transmission_start_time

        plaintext = "This is exactly thirty-two char."
        encrypted_message = encrypt_message(plaintext)

        print(f"Sending encrypted message: {binascii.hexlify(encrypted_message).decode()}")

        # Track transmission start time
        transmission_start_time = time.ticks_ms()
        message_id = client.post("192.168.1.100", 5684, "iot", encrypted_message)

        print(f"Message Sent. Message ID: {message_id}")

        # Monitor storage usage
        used_storage, total_storage = monitor_storage()
        print(f"Used storage: {used_storage} bytes / Total storage: {total_storage} bytes")

        await asyncio.sleep(10)  # Send message every 10 seconds

    client.stop()

# CoAP Response Callback
def response_callback(packet, sender):
    global transmission_start_time

    print(f"Message received from {sender}: {packet.payload}")

    decrypted_message = decrypt_message(packet.payload)
    print(f"Decrypted message: {decrypted_message}")

    # Calculate transmission time
    transmission_end_time = time.ticks_ms()
    transmission_time = time.ticks_diff(transmission_end_time, transmission_start_time)
    print(f"Transmission time: {transmission_time} ms")

# Main function to run both sender and receiver tasks
async def main():
    receiver = asyncio.create_task(receiver_task())
    sender = asyncio.create_task(sender_task())
    await asyncio.gather(receiver, sender)

if __name__ == "__main__":
    asyncio.run(main())

