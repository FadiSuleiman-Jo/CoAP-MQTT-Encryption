import asyncio
import aiocoap.resource as resource
import aiocoap
import binascii
from Simon_Cipher import simonCipher  # Import your SIMON cipher implementation

# SIMON decryption setup
key = 0x0f0e0d0c0b0a09080706050403020100  # Key for SIMON-128/128
cipher = simonCipher(key, 128, 128)  # Create an instance of the cipher

def decrypt_message(encrypted_hex):
    # Decrypt the hex message using the SIMON cipher
    decrypted_msg = cipher.decrypt(int(encrypted_hex, 16))

    # Convert the decrypted message back to hexadecimal and remove padding
    decrypted_hex = hex(decrypted_msg)[2:].rstrip('0')
    
    # Convert hexadecimal back to plaintext string
    plaintext = binascii.unhexlify(decrypted_hex).decode()
    return plaintext

class EncryptedDataResource(resource.Resource):
    async def render_post(self, request):
        # Log the received encrypted payload
        encrypted_payload = request.payload.hex()
        print(f"Received Ciphertext: {encrypted_payload}")

        # Decrypt the received data
        try:
            # Decrypt the message
            plaintext = decrypt_message(encrypted_payload)
            print(f"Decrypted Plaintext: {plaintext}")

            # Return the plaintext back as a response (optional)
            return aiocoap.Message(payload=plaintext.encode())

        except Exception as e:
            print(f"Decryption failed: {e}")
            return aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR, payload=b'Failed to decrypt')

async def main():
    # Resource tree creation
    root = resource.Site()

    # Add resource handler for /iot endpoint
    root.add_resource(['iot'], EncryptedDataResource())

    # Create and bind CoAP server
    await aiocoap.Context.create_server_context(root, bind=('0.0.0.0', 5683))
    print("CoAP server running on port 5683")

    # Serve forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())