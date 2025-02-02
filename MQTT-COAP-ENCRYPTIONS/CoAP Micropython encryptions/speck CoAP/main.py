from machine import unique_id
import binascii
import uos
import utime as time
import gc  # Import garbage collection module
from Speck_Cipher_Module import speckCipher  # Import your SPECK implementation
from microcoapy import Coap  # Import microcoapy library

# SPECK encryption setup
key = 0x0f0e0d0c0b0a09080706050403020100  # 128-bit key
cipher = speckCipher(key, 128, 128)  # Initialize SPECK cipher with block size and key size

def pad_hex_string(hex_str, target_length):
    """
    Custom function to pad a hex string to the target length with leading zeros.
    """
    padding_length = target_length - len(hex_str)
    if padding_length > 0:
        hex_str = '0' * padding_length + hex_str
    return hex_str

def encrypt_message(plaintext):
    """
    Encrypt the plaintext message using SPECK cipher and measure encryption time and memory usage.
    """
    # Convert the plaintext to hex
    hex_plaintext = binascii.hexlify(plaintext.encode()).decode()
    print(f"Hex plaintext: {hex_plaintext}")

    # Pad the message to 128 bits (16 bytes => 32 hex characters)
    while len(hex_plaintext) < 32:
        hex_plaintext += '0'
    print(f"Padded hex plaintext: {hex_plaintext}")

    # Force garbage collection and get memory before encryption
    gc.collect()
    mem_free_before = gc.mem_free()
    print(f"Free memory before encryption: {mem_free_before} bytes")

    # Measure the start time of encryption in milliseconds
    encryption_start_time = time.ticks_ms()

    # Encrypt the padded message
    encrypted_msg_int = cipher.encrypt(int(hex_plaintext, 16))

    # Measure the end time of encryption
    encryption_end_time = time.ticks_ms()

    # Calculate encryption time in milliseconds
    encryption_time_ms = time.ticks_diff(encryption_end_time, encryption_start_time)

    # Convert the encrypted message to hex and pad
    encrypted_msg_hex = hex(encrypted_msg_int)[2:].rstrip('L')  # Remove '0x' prefix and 'L' suffix if any
    encrypted_msg_hex = pad_hex_string(encrypted_msg_hex, 32)  # Ensure even length for 16 bytes

    # Force garbage collection and get memory after encryption
    gc.collect()
    mem_free_after = gc.mem_free()
    print(f"Free memory after encryption: {mem_free_after} bytes")

    # Calculate memory used during encryption
    mem_used = mem_free_before - mem_free_after

    print(f"Encryption time: {encryption_time_ms} ms")
    print(f"Memory used during encryption: {mem_used} bytes")
    print(f"Encrypted message (hex): {encrypted_msg_hex}")

    return encrypted_msg_hex

def send_coap_message():
    """
    Encrypt the message and send it over CoAP.
    """
    # Prepare the plaintext
    plaintext = "hello world"
    print(f"Original message: {plaintext}")

    # Encrypt the plaintext
    encrypted_message_hex = encrypt_message(plaintext)
    print(f"Encrypted message: {encrypted_message_hex}")

    # Convert encrypted message to bytes to send over CoAP
    ciphertext = bytes.fromhex(encrypted_message_hex)  # No need to remove '0x' since we already stripped it
    print(f"Encrypted ciphertext bytes: {ciphertext}")

    # Initialize CoAP client
    coap = Coap()
    coap.debug = True  # Optional, to see detailed logs
    coap.start()
    print("CoAP client started.")

    # Define CoAP server IP, port, and URL
    ip = "0.0.0.0"
    port = 5683
    url = "iot"

    try:
        # Send POST request with encrypted message as payload
        message_id = coap.post(ip=ip, port=port, url=url, payload=ciphertext, content_format=0)
        
        if message_id != 0:
            print(f"Message sent successfully with ID: {message_id}")
        else:
            print("Failed to send message.")

        # Poll for the response
        coap.poll(2000)  # Wait for 2 seconds for any response
        print("Polling for response...")

    except Exception as e:
        print(f"Failed to send CoAP request: {e}")

    finally:
        # Stop the CoAP client
        coap.stop()
        print("CoAP client stopped.")

if __name__ == "__main__":
    send_coap_message()