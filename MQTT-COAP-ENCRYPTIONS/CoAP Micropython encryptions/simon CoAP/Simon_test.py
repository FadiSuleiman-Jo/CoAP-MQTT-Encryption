from Simon_Cipher import simonCipher
from colorama import init,deinit,Fore,Style
import binascii
init()

#SIMON32/64
print("Original plaintext: " + str(hex(0x65656877)))
simon = simonCipher(0x1918111009080100,32,64)
encrypted = simon.encrypt(0x65656877)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xc69be9bb and decrypted == 0x65656877):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON48/72
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x6120676e696c)))
simon = simonCipher(0x1211100a0908020100,48,72)
encrypted = simon.encrypt(0x6120676e696c)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xdae5ac292cac and decrypted == 0x6120676e696c):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON48/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x72696320646e)))
simon = simonCipher(0x1a19181211100a0908020100,48,96)
encrypted = simon.encrypt(0x72696320646e)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x6e06a5acf156 and decrypted == 0x72696320646e):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON64/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x6f7220676e696c63)))
simon = simonCipher(0x131211100b0a090803020100,64,96)
encrypted = simon.encrypt(0x6f7220676e696c63)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x5ca2e27f111a8fc8 and decrypted == 0x6f7220676e696c63):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON64/128
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x656b696c20646e75)))
simon = simonCipher(0x1b1a1918131211100b0a090803020100,64,128)
encrypted = simon.encrypt(0x656b696c20646e75)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x44c8fc20b9dfa07a and decrypted == 0x656b696c20646e75):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON96/96
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x48656c6c6f20576f726c6420)))
simon = simonCipher(0x0d0c0b0a0908050403020100,96,96)
encrypted = simon.encrypt(0x48656c6c6f20576f726c6420)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xecad1c6c451e3f59c5db1ae9 and decrypted == 0x48656c6c6f20576f726c6420):
    print(simon.key_schedule)
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON96/144
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x74616874207473756420666f)))
simon = simonCipher(0x1514131211100d0c0b0a0908050403020100,96,144)
encrypted = simon.encrypt(0x74616874207473756420666f)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xecad1c6c451e3f59c5db1ae9 and decrypted == 0x74616874207473756420666f):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON128/128
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x63736564207372656c6c657661727420)))
simon = simonCipher(0x0f0e0d0c0b0a09080706050403020100,128,128)
encrypted = simon.encrypt(0x63736564207372656c6c657661727420)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x49681b1e1e54fe3f65aa832af84e0bbc and decrypted == 0x63736564207372656c6c657661727420):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

    from binascii import hexlify, unhexlify
import math

import binascii  # Import binascii module for hexlify and unhexlify

# SIMON128/128 cipher class, assuming simonCipher is already implemented

# Step 1: Convert "hello world" into hexadecimal
def str_to_hex(plaintext):
    return binascii.hexlify(plaintext.encode()).decode()

# Step 2: Padding function to pad the plaintext to 128 bits (16 bytes)
def pad_to_128_bits(hex_str):
    num_bytes = len(hex_str) // 2
    pad_len = 16 - num_bytes  # We need 16 bytes (128 bits)
    pad = pad_len * '{:02x}'.format(pad_len)  # PKCS#7 padding format
    padded_hex_str = hex_str + pad
    return padded_hex_str

# Step 5: Unpad after decryption
def unpad_128_bits(padded_hex_str):
    pad_len = int(padded_hex_str[-2:], 16)  # PKCS#7 padding byte
    unpadded_hex_str = padded_hex_str[:-pad_len*2]
    return unpadded_hex_str

# Step 6: Convert hex back to string
def hex_to_str(hex_str):
    return binascii.unhexlify(hex_str).decode()

# Example plaintext "hello world"
plaintext = "hello world"
print("Original plaintext:", plaintext)

# Step 1: Convert plaintext to hexadecimal
hex_plaintext = str_to_hex(plaintext)
print("Hexadecimal representation:", hex_plaintext)

# Step 2: Pad the hexadecimal plaintext to 128 bits
padded_hex_plaintext = pad_to_128_bits(hex_plaintext)
print("Padded hexadecimal (128 bits):", padded_hex_plaintext)

# Convert padded hex to int for encryption
padded_plaintext_int = int(padded_hex_plaintext, 16)

# SIMON128/128 encryption
simon = simonCipher(0x0f0e0d0c0b0a09080706050403020100, 128, 128)
encrypted = simon.encrypt(padded_plaintext_int)
print("Encrypted:", hex(encrypted))

# Step 4: Decrypt the ciphertext
decrypted = simon.decrypt(encrypted)
print("Decrypted (hex):", hex(decrypted))

# Convert decrypted integer back to hexadecimal string
decrypted_hex_str = '{:032x}'.format(decrypted)  # Ensure it has 128 bits
print("Decrypted hex string:", decrypted_hex_str)

# Step 5: Remove the padding
unpadded_decrypted_hex = unpad_128_bits(decrypted_hex_str)
print("Unpadded decrypted hex:", unpadded_decrypted_hex)

# Step 6: Convert the unpadded hex back to plaintext
recovered_plaintext = hex_to_str(unpadded_decrypted_hex)

# Step 7: Print the recovered plaintext
print("Recovered plaintext:", recovered_plaintext)

#SIMON128/192
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x206572656874206e6568772065626972)))
simon = simonCipher(0x17161514131211100f0e0d0c0b0a09080706050403020100,128,192)
encrypted = simon.encrypt(0x206572656874206e6568772065626972)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0xc4ac61effcdc0d4f6c9c8d6e2597b85b and decrypted == 0x206572656874206e6568772065626972):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

#SIMON128/256
print(Style.RESET_ALL + "Original plaintext: " + str(hex(0x74206e69206d6f6f6d69732061207369)))
simon = simonCipher(0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,128,256)
encrypted = simon.encrypt(0x74206e69206d6f6f6d69732061207369)
decrypted = simon.decrypt(encrypted)
if (encrypted == 0x8d2b5579afc8a3a03bf72a87efe7b868 and decrypted == 0x74206e69206d6f6f6d69732061207369):
    print(Fore.GREEN + "Test Passed\n")
else:
    print(Fore.RED + "Test Failed")

print(Style.RESET_ALL)
deinit()