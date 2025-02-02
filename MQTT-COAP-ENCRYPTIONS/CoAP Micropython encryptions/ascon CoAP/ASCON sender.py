import asyncio
import aiocoap.resource as resource
import aiocoap
from ascon import ascon_decrypt, ascon_encrypt

# Test encrypting and decrypting a string and sending it via CoAP
async def main():
    key = b"thisis16bytekey!"  # 16 bytes for Ascon-128
    nonce = b"unique16bytesstr"  # 16 bytes nonce
    associateddata = b""  # No associated data in this example
    plaintext = b"testing123"

    # Encrypt the plaintext
    ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext)
    print("Ciphertext:", ciphertext)

    # Prepare CoAP message
    context = await aiocoap.Context.create_client_context()
    payload = ciphertext

    request = aiocoap.Message(
        code=aiocoap.POST,
        payload=payload,
        uri=f"coap://0.0.0.0/iot"
    )

    try:
        # Send the CoAP request
        response = await context.request(request).response
        print(f"Response Code: {response.code}")
        print(f"Response Payload: {response.payload}")

        # Check if the response is empty or if an error occurred
        if response.code.is_successful() and response.payload:
            # Optionally decrypt the response (if applicable)
            decrypted = ascon_decrypt(key, nonce, associateddata, response.payload)
            print("Decrypted:", decrypted)
        else:
            print("Error or empty response. Cannot decrypt.")

    except Exception as e:
        print(f"Failed to send CoAP request or decrypt: {e}")

if __name__ == "__main__":
    asyncio.run(main())