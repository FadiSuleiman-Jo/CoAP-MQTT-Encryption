import asyncio
from aiocoap import *
from aiocoap import resource
import json
import struct

# ChaCha20 decryption functions
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

    # Ensure the key is exactly 32 bytes
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")

    ctx = [0] * 16
    ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)
    ctx[4:12] = struct.unpack('<8L', key)  # Unpack the 32-byte key into 8 4-byte integers
    ctx[12] = ctx[13] = position
    ctx[14:16] = struct.unpack('<LL', iv)  # IV must be 8 bytes
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
        for c in struct.pack('<16L', *((x[i] + ctx[i]) & 0xffffffff for i in range(16))):
            yield c
        ctx[12] = (ctx[12] + 1) & 0xffffffff
        if ctx[12] == 0:
            ctx[13] = (ctx[13] + 1) & 0xffffffff

def chacha20_decrypt(data, key, iv, position=0):
    return bytes(a ^ b for a, b in zip(data, yield_chacha20_xor_stream(key, iv, position)))

# Replace these with the same key and IV used in the sender, ensuring key is 32 bytes
KEY = bytes.fromhex('3f8e12a1b7429df64e8d75f5a36f8b9c2d4d21a7f1b97e68c0d3f5b8cd9a7642')
IV = bytes.fromhex('f5a4b8c2394e8d32')

class CoAPResource(resource.Resource):
    async def render_post(self, request):
        # Decrypt the incoming payload
        encrypted_payload = request.payload
        decrypted_payload = chacha20_decrypt(encrypted_payload, KEY, IV)

        try:
            # Decode the decrypted payload as UTF-8 and parse as JSON
            payload = decrypted_payload.decode('utf-8')
            data = json.loads(payload)

            print(f"Received IoT data: {data}")

            response_payload = b"Data received successfully"
        except UnicodeDecodeError as e:
            print(f"Failed to decode decrypted payload: {e}")
            response_payload = b"Failed to decode payload"
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON from decrypted payload: {e}")
            response_payload = b"Failed to parse JSON"

        return Message(payload=response_payload)

async def main():
    # Create a CoAP server context
    root = resource.Site()
    root.add_resource(['.well-known', 'core'], resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['iot'], CoAPResource())
    context = await Context.create_server_context(root, bind=('0.0.0.0', 5683))  # Bind to all interfaces

    print("CoAP server running on port 5683")
    
    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())