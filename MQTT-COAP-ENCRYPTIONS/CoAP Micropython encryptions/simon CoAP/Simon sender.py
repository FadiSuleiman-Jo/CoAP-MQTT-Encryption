import asyncio
import aiocoap
import binascii
from Simon_Cipher import simonCipher  # Make sure to import your SIMON implementation

# SIMON encryption setup
key = 0x0f0e0d0c0b0a09080706050403020100
cipher = simonCipher(key, 128, 128)

def encrypt_message(plaintext):
    # Convert the plaintext to hex and pad if necessary
    hex_plaintext = binascii.hexlify(plaintext.encode()).decode()
    
    # Pad the message to 128 bits (16 bytes)
    while len(hex_plaintext) < 32:
        hex_plaintext += '0'
    
    # Encrypt the padded message
    encrypted_msg = cipher.encrypt(int(hex_plaintext, 16))
    return hex(encrypted_msg)

async def send_coap_message(uri, ciphertext):
    context = await aiocoap.Context.create_client_context()

    request = aiocoap.Message(
        code=aiocoap.POST,
        payload=ciphertext,
        uri=uri
    )

    try:
        # Send the CoAP request
        response = await context.request(request).response
        print(f"Response Code from {uri}: {response.code}")
        print(f"Response Payload from {uri}: {response.payload}")

        # Optionally handle and decrypt the response (if applicable)
        if response.code.is_successful() and response.payload:
            # Here you could decrypt the response if needed
            print("Received response:", response.payload)
        else:
            print(f"Error or empty response from {uri}. Cannot process further.")

    except Exception as e:
        print(f"Failed to send CoAP request to {uri}: {e}")

async def main():
    # Prepare the plaintext
    plaintext = "hello world"
    print(f"Original message: {plaintext}")

    # Encrypt the plaintext
    encrypted_message = encrypt_message(plaintext)
    print(f"Encrypted message: {encrypted_message}")

    # Convert encrypted message to bytes to send over CoAP
    ciphertext = bytes.fromhex(encrypted_message[2:])  # Remove '0x' from hex

    # URIs of the two receivers
    uri_receiver_1 = "coap://0.0.0.0:5683/iot"

    # Send messages to both receivers
    await asyncio.gather(
        send_coap_message(uri_receiver_1, ciphertext))

if __name__ == "__main__":
    asyncio.run(main())