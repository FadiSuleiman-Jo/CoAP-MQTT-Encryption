import paho.mqtt.client as mqtt
import struct
import json

# ChaCha20 decryption function (same as encryption)
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

def chacha20_decrypt(data, key, iv, position=0):
    return bytes(a ^ b for a, b in zip(data, yield_chacha20_xor_stream(key, iv, position)))

# MQTT broker details
broker = "192.168.1.14"  # Use your broker's IP or hostname
port = 1883
topic = "iot/sensor"

# MQTT message callback for decrypting
def on_message(client, userdata, message):
    print(f"Received encrypted message: {message.payload}")
    
    # Use the same key and IV to decrypt
    key = bytes.fromhex('3f8e12a1b7429df64e8d75f5a36f8b9c2d4d21a7f1b97e68c0d3f5b8cd9a7642')  # 32-byte key
    iv = bytes.fromhex('f5a4b8c2394e8d32')  # 8-byte IV

    decrypted_message = chacha20_decrypt(message.payload, key, iv)
    print(f"Decrypted message: {decrypted_message.decode('utf-8')}")

# Create an MQTT client and subscribe to the topic
client = mqtt.Client()
client.on_message = on_message

client.connect(broker, port, 60)
client.subscribe(topic)

# Start the MQTT loop
client.loop_forever()
