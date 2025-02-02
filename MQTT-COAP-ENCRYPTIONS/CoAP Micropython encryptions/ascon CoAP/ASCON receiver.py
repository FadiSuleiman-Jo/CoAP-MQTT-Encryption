import asyncio
import aiocoap.resource as resource
import aiocoap
from ascon import ascon_decrypt
import time  # Import time module for measuring decryption time

class EncryptedDataResource(resource.Resource):
    async def render_post(self, request):
        key = b"thisis16bytekey!"  # 16 bytes for Ascon-128
        nonce = b"unique16bytesstr"  # 16 bytes nonce
        associateddata = b""  # No associated data in this example

        # Log the received encrypted payload
        ciphertext = request.payload
        print(f"Received Ciphertext: {ciphertext}")

        # Measure the start time of decryption
        start_time = time.time()

        # Decrypt the received data
        try:
            plaintext = ascon_decrypt(key, nonce, associateddata, ciphertext)

            # Measure the end time of decryption
            end_time = time.time()

            # Calculate decryption time
            decryption_time = end_time - start_time
            print(f"Decrypted Plaintext: {plaintext}")
            print(f"Time taken to decrypt: {decryption_time:.6f} seconds")

            # Send an acknowledgment packet (optional payload can be added)
            ack_message = f"Acknowledgment: Data received and decrypted in {decryption_time:.6f} seconds."
            return aiocoap.Message(payload=ack_message.encode('utf-8'))

        except Exception as e:
            print(f"Decryption failed: {e}")
            return aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR, payload=b'Failed to decrypt')

async def main():
    # Resource tree creation
    root = resource.Site()

    # Add resource handler for /iot endpoint
    root.add_resource(['iot'], EncryptedDataResource())

    # Create and bind CoAP server
    await aiocoap.Context.create_server_context(root, bind=('192.168.1.14', 5683))

    # Serve forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())