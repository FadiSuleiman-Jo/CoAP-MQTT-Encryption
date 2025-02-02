#! /usr/bin/python3
import struct
import asyncio
import time
from aiocoap import *
import json

# ChaCha20 encryption functions
def yield_chacha20_xor_stream(key, iv, position=0):
    """Generate the xor stream with the ChaCha20 cipher."""
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
    """Encrypt (or decrypt) with the ChaCha20 cipher."""
    return bytes(a ^ b for a, b in zip(data, yield_chacha20_xor_stream(key, iv, position)))

async def send_coap_message(encrypted_message, timings):
    """Send the encrypted message using CoAP and record the time taken."""
    context = await Context.create_client_context()

    # Create the request and send to the server
    request = Message(code=POST, payload=encrypted_message)
    request.set_request_uri('coap://0.0.0.0:5683/iot')

    # Measure send time
    send_time_start = time.time()

    try:
        response = await context.request(request).response
        timings['send_receive_time'] = (time.time() - send_time_start) * 1000  # time in ms
        print('Response: %s\n%r' % (response.code, response.payload))
    except Exception as e:
        print('Failed to send CoAP request: %s' % e)

def main():
    # Replace these with the same key and IV used in the server
    key = bytes.fromhex('3f8e12a1b7429df64e8d75f5a36f8b9c2d4d21a7f1b97e68c0d3f5b8cd9a7642')  # 32 bytes key
    iv = bytes.fromhex('f5a4b8c2394e8d32')  # 8 bytes IV
    message = json.dumps({"temperature": 25}).encode('utf-8')  # message to encrypt as JSON

    # Timing dictionary to store durations
    timings = {}

    # Measure encryption time
    encryption_start = time.time()
    encrypted_message = chacha20_encrypt(message, key, iv)
    timings['encryption_time'] = (time.time() - encryption_start) * 1000  # time in ms

    print(f"Encrypted: {encrypted_message}")
    print(f"Encryption time: {timings['encryption_time']} ms")

    # Send the encrypted message over CoAP
    asyncio.run(send_coap_message(encrypted_message, timings))

    # Display overall timings
    print(f"Time to encrypt, send, and receive: {timings['encryption_time'] + timings['send_receive_time']} ms")
    print(f"Send and receive time: {timings['send_receive_time']} ms")

if __name__ == "__main__":
    main()