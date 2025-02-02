import asyncio
import aiocoap
import aiocoap.resource as resource
import logging

# Encryption and Decryption Functions (same as receiver)

s_box = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
inv_sbox = [s_box.index(x) for x in range(len(s_box))]
p_box = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38,
         54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13,
         29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]
inv_p_box = [p_box.index(x) for x in range(64)]
rounds = 32

def sBox4Layer(state):
    sub_block = ""
    state = hex(int(state, 2))
    sub_block += str(hex(s_box[int(state, 16)])[2])
    sub_block = int(sub_block, 16)
    x = '{0:04b}'.format(sub_block)
    return x

def sBoxLayer(state):
    sub_block = ""
    for i in range(len(state)):
        sub_block += str(hex(s_box[int(state[i], 16)])[2])
    return int(sub_block, 16)

def sBoxLayerInverse(state):
    sub_block = ""
    for i in range(len(state)):
        sub_block += str(hex(inv_sbox[int(state[i], 16)])[2])
    return int(sub_block, 16)

def pLayer(state):
    state = bin(state)[2:].zfill(64)
    perm_list = [0 for x in range(64)]
    for i in range(64):
        perm_list[p_box[i]] = state[i]
    perm_block = ''.join(perm_list)
    return int(perm_block, 2)

def pLayerInverse(state):
    state = bin(state)[2:].zfill(64)
    perm_list = [0 for x in range(64)]
    for i in range(64):
        perm_list[inv_p_box[i]] = state[i]
    perm_block = ''.join(perm_list)
    return int(perm_block, 2)

def xor2strings(string, count):
    y = '{0:05b}'.format(int(string, 2) ^ count)
    return y

def generateRoundKeys(key):
    K = []
    string = bin(key)[2:].zfill(80)
    K.append(int(string[:64], 2))
    for i in range(0, 31):
        string = string[61:] + string[:61]
        string = sBox4Layer(string[:4]) + string[4:]
        string = string[:60] + xor2strings(string[60:65], i + 1) + string[65:]
        K.append(int(string[0:64], 2))
    return K

def addRoundKey(state, K64):
    x = state ^ K64
    return x

def encrypt(state, K):
    for i in range(rounds - 1):
        state = addRoundKey(state, K[i])
        state = hex(state)[2:].zfill(16)
        state = sBoxLayer(state)
        state = pLayer(state)
    state = addRoundKey(state, K[31])
    return state

def decrypt(state, K):
    for i in range(rounds - 1):
        state = addRoundKey(state, K[-i - 1])
        state = pLayerInverse(state)
        state = hex(state)[2:].zfill(16)
        state = sBoxLayerInverse(state)
    state = addRoundKey(state, K[0])
    return state

def string_to_hex(s):
    return int(s.encode('utf-8').hex(), 16)

def hex_to_string(h):
    hex_str = '{0:016x}'.format(h)
    try:
        return bytes.fromhex(hex_str).decode('utf-8').rstrip()
    except UnicodeDecodeError:
        return ''.join([chr(b) for b in bytes.fromhex(hex_str) if 32 <= b <= 126]).rstrip()

def pad(plaintext, block_size=8):
    pad_len = block_size - len(plaintext) % block_size
    return plaintext + chr(pad_len) * pad_len

def unpad(padded_text):
    pad_len = ord(padded_text[-1])
    return padded_text[:-pad_len]

def encrypt_message(plain_text, K):
    padded_text = pad(plain_text)
    cipher_texts = []
    for i in range(0, len(padded_text), 8):
        block = padded_text[i:i + 8]
        plain_block = string_to_hex(block)
        cipher_block = encrypt(plain_block, K)
        cipher_texts.append(cipher_block)
    return cipher_texts

def decrypt_message(cipher_texts, K):
    decrypted_text = ""
    for cipher_block in cipher_texts:
        decrypted_block = decrypt(cipher_block, K)
        decrypted_text += hex_to_string(decrypted_block)
    return unpad(decrypted_text)

# CoAP Client (Sender) to send encrypted data
class CoAPSender:
    def __init__(self, uri):
        self.uri = uri

    async def post(self, plain_text):
        # Encrypt the plaintext
        key = 0xFFFFFFFFFFFFFFFFFFFF  # Example key
        K = generateRoundKeys(key)
        cipher_texts = encrypt_message(plain_text, K)

        # Prepare the payload (cipher text) as space-separated hex blocks
        encrypted_payload = " ".join(hex(cipher)[2:] for cipher in cipher_texts).encode('utf-8')

        # Create a CoAP request message
        request = aiocoap.Message(code=aiocoap.POST, payload=encrypted_payload)
        request.set_request_uri(self.uri)

        # Send the POST request to the server
        protocol = await aiocoap.Context.create_client_context()
        response = await protocol.request(request).response

        # Print the server's response
        print(f"Response Code: {response.code}")
        print(f"Response Payload: {response.payload.decode('utf-8')}")

# Main function to run the sender
async def main():
    server_uri = "coap://192.168.1.14/iot"  # Example URI

    # Create a sender instance
    sender = CoAPSender(server_uri)

    # Plain text message to encrypt and send
    plain_text = "hello, this is a wall of text"

    # Send the encrypted message
    await sender.post(plain_text)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())