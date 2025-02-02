import asyncio
import aiocoap.resource as resource
import aiocoap
import binascii
from Speck_Cipher import speckCipher  # Ensure this module is compatible with your Python environment

# SPECK decryption setup
key = 0x0f0e0d0c0b0a09080706050403020100
cipher = speckCipher(key, 128, 128)

def split_into_blocks(data, block_size):
    """
    Split data into fixed-size blocks.
    """
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def decrypt_message(ciphertext, block_size=128):
    """
    Decrypt the ciphertext (bytes) and return the plaintext string.
    """
    # Split ciphertext into blocks (16 bytes for 128 bits)
    block_byte_size = block_size // 8
    ciphertext_blocks = split_into_blocks(ciphertext, block_byte_size)
    print(f"Ciphertext blocks: {ciphertext_blocks}")

    decrypted_bytes = b''

    for block in ciphertext_blocks:
        # Convert block to integer
        ciphertext_int = int.from_bytes(block, byteorder='big')
        # Decrypt block
        decrypted_int = cipher.decrypt(ciphertext_int)
        # Convert decrypted integer to hex, pad with zeros to ensure even length
        decrypted_hex = hex(decrypted_int)[2:].rstrip('L')  # Remove '0x' prefix and 'L' suffix if any
        decrypted_hex = decrypted_hex.zfill(block_byte_size * 2)  # Ensure even length
        # Convert hex to bytes
        decrypted_block = bytes.fromhex(decrypted_hex)
        decrypted_bytes += decrypted_block
        print(f"Decrypted block: {decrypted_block}")

    # Remove padding
    decrypted_message = decrypted_bytes.rstrip(b'\x00')
    try:
        decrypted_str = decrypted_message.decode('utf-8')
    except UnicodeDecodeError:
        decrypted_str = "Error decoding message"

    return decrypted_str

class IoTResource(resource.Resource):
    async def render_post(self, request):
        # Decrypt the received message
        decrypted_message = decrypt_message(request.payload)
        print(f"Decrypted message: {decrypted_message}")

        # Send a response back to the sender
        response_payload = f"Decrypted message: {decrypted_message}".encode('utf-8')
        return aiocoap.Message(payload=response_payload)

async def main():
    root = resource.Site()
    root.add_resource(['iot'], IoTResource())

    await aiocoap.Context.create_server_context(root, bind=('192.168.1.14', 5683))

    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())
