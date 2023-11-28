"""
Task 2 of Assignment 1
Author: Gregory Newman

For this part of the assignment, I initially started by setting the key to each line
of the file, attempting to decrypt the ciphertext, and seeing if the resulting
plaintext matched. However, I could not get this to work, so I switched to
trying to encrypt the plaintext with each key and see if the resulting ciphertext
matched the given ciphertext.
"""

import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

plaintext = b"This is a top secret."
padder = PKCS7(128).padder() 
# Pads the plaintext so it is in multiples of 16 bytes to fit the block cipher
padded_plaintext = padder.update(plaintext) + padder.finalize() 
ciphertext = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9"
# Converts the hex to bytes so the encryptor can read it
ciphertext_bytes = bytes.fromhex(
    "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9")

# Reads the file containing the possible keys
words = open('words.txt', 'r')
Lines = words.readlines()
words.close()

zero_iv = b'\x00' * 16 # Creates the initialization vector (all 0's)

for line in Lines:
    keyFound = False
    # line will be modified, so store the original string
    line = line.strip()  # Strips newline character
    original_line = line # Stores original line before space padding is added
    if len(line) <= 16:
        print("Trying word: [" + line + "] as key: ")
        spacesToAdd = 16 - len(line)  # Calculates number of spaces to add
        line = line + (" " * spacesToAdd)
        line = line.encode("utf-8")

        # Initializes the cipher with the current line as the key
        cipher = Cipher(algorithms.AES(line), modes.CBC(zero_iv))
        encryptor = cipher.encryptor()
        # Encrypts the plaintext and sends the result to a variable
        result = encryptor.update(padded_plaintext) + encryptor.finalize()
        hex_result = binascii.hexlify(result) # Changes binary result back to hex
        hex_result = hex_result.decode("utf-8") # Decodes the utf-8 encoding to display the ciphertext

        if hex_result == ciphertext:
            print("Key was: " + original_line)
            keyFound = True
            break

if keyFound == False:
    print("Key not found.")

