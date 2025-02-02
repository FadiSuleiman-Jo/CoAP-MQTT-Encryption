import uasyncio as asyncio
import microcoapy
import struct
import time
import gc
import uos

# Constants for CoAP communication
_RECEIVER_IP = '192.168.1.100'  # Receiver's IP address (ESP32)
_RECEIVER_PORT = 5684  # Port for the receiver to listen on
_SENDER_IP = '192.168.1.100'  # Sender's IP address (ESP32)
_SENDER_PORT = 9000  # Port for the sender
_COAP_POST_URL = '/iot'

# Global transmission time variable
transmission_start_time = None

# Define the payload to be sent
payload = b"This message is exactly one hundred and twenty-eight characters long. It's used for testing message encryption or transmission length."

# Global key and IV for ChaCha20 encryption
key = bytes.fromhex('3f8e12a1b7429df64e8d75f5a36f8b9c2d4d21a7f1b97e68c0d3f5b8cd9a7642')
iv = bytes.fromhex('f5a4b8c2394e8d32')

# ChaCha20 encryption function
def yield_chacha20_xor_stream(key, iv, position=0):
    if not isinstance(position, int):
        raise TypeError
    if position & ~0xffffffff:
        raise ValueError('Position is not uint32.')
    if not isinstance(key, bytes):
        raise TypeError
    if not isinstance(iv, bytes):
        raise TypeError
    if len(key) != 32:
        raise ValueError('Key must be 32 bytes.')
    if len(iv) != 8:
        raise ValueError('IV must be 8 bytes.')

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

    while 1:
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

        for c in struct.pack('<16L', *((x[i] + ctx[i]) & 0xffffffff for i in range(16))):
            yield c

        ctx[12] = (ctx[12] + 1) & 0xffffffff
        if ctx[12] == 0:
            ctx[13] = (ctx[13] + 1) & 0xffffffff

def chacha20_encrypt(data, key, iv=None, position=0):
    if not isinstance(data, bytes):
        raise TypeError
    if iv is None:
        iv = b'\0' * 8

    return bytes(a ^ b for a, b in zip(data, yield_chacha20_xor_stream(key, iv, position)))

# Sender task to send CoAP messages after a 5-second delay
async def sender_task():
    global transmission_start_time

    await asyncio.sleep(5)  # Wait 5 seconds before starting the sender

    client = microcoapy.Coap()
    client.discardRetransmissions = True

    client.start(port=_SENDER_PORT)  # Start CoAP client on sender port

    while True:
        # Record memory before encryption
        gc.collect()
        mem_before_encryption = gc.mem_free()

        # Encrypt the payload using ChaCha20
        start_time = time.ticks_ms()  # Use milliseconds
        encrypted_payload = chacha20_encrypt(payload, key, iv)
        encryption_time = time.ticks_diff(time.ticks_ms(), start_time)
        print("Encryption time (ms):", encryption_time)

        # Record memory after encryption
        gc.collect()
        mem_after_encryption = gc.mem_free()
        mem_used_for_encryption = mem_before_encryption - mem_after_encryption
        print("Memory used during encryption:", mem_used_for_encryption, "bytes")

        # Measure storage usage
        stats = uos.statvfs('/')
        total_storage = stats[0] * stats[2]
        free_storage = stats[0] * stats[3]
        used_storage = total_storage - free_storage
        print(f"Storage used: {used_storage} bytes, Free storage: {free_storage} bytes")

        print("Sending CoAP POST request with encrypted payload...")
        # Set the transmission start time
        transmission_start_time = time.ticks_ms()

        # Send to receiver IP (_RECEIVER_IP) and receiver port (_RECEIVER_PORT)
        message_id = client.post(_RECEIVER_IP, _RECEIVER_PORT, _COAP_POST_URL, encrypted_payload, None)
        print(f"[POST] Message Id: {message_id}")

        await asyncio.sleep(10)  # Send message every 10 seconds

    client.stop()

# Receiver task to listen for CoAP messages and decrypt them
async def receiver_task():
    client = microcoapy.Coap()
    client.discardRetransmissions = True
    client.responseCallback = received_message_callback

    client.start(port=_RECEIVER_PORT)  # Start CoAP client on receiver port

    while True:
        client.poll(1000)  # Poll for messages every second
        await asyncio.sleep(1)

    client.stop()

# Callback to handle received messages and decrypt them
def received_message_callback(packet, sender):
    global transmission_start_time

    print(f"Message received from {sender}: {packet.payload}")

    # Record memory before decryption
    gc.collect()
    mem_before_decryption = gc.mem_free()

    # Measure transmission time
    if transmission_start_time:
        transmission_end_time = time.ticks_ms()
        transmission_time = time.ticks_diff(transmission_end_time, transmission_start_time)
        print(f"Transmission time (ms): {transmission_time}")
        transmission_start_time = None

    # Decrypt the received payload
    start_time = time.ticks_ms()
    decrypted_payload = chacha20_encrypt(packet.payload, key, iv)
    decryption_time = time.ticks_diff(time.ticks_ms(), start_time)
    print("Decrypted Payload:", decrypted_payload)
    print("Decryption time (ms):", decryption_time)

    # Record memory after decryption
    gc.collect()
    mem_after_decryption = gc.mem_free()
    mem_used_for_decryption = mem_before_decryption - mem_after_decryption
    print("Memory used during decryption:", mem_used_for_decryption, "bytes")

# Main function to start both sender and receiver tasks
async def main():
    receiver = asyncio.create_task(receiver_task())
    sender = asyncio.create_task(sender_task())

    await asyncio.gather(receiver, sender)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Error running main: {e}")

