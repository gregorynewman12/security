import binascii
import struct
import qrcode
import sys
import time
import base64
import hashlib
import hmac
import os
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

salt = b'$2b$12$Ij74FyWks8sNAvWbGEs91O' # A constant salt value for password storage.
                                        # The hashed password is stored in secret.txt
storageKey = "ZYXWVUTSRQPONMLK" # ECB key used to encrypt the OTP generation key.
                                # It is stored encrypted in secret.txt

def makeQRCode():
    key = base64.b32encode(os.urandom(10)) # Generates random OTP generation key
    uri = "otpauth://totp/Gregory:newmangr?secret=" + key.decode() + "&issuer=Gregory" # Makes URI GA expects
    qrcode.make(uri).save("qrcode.jpg") # Outputs uri to a qrcode
    key = key.decode() # Converts from bytes to str

    padder = PKCS7(128).padder()
    padded_key = padder.update(key.encode()) + padder.finalize() # Pads OTP key to appropriate size
    cipher = Cipher(algorithms.AES(storageKey.encode()), modes.ECB()) # Creates cipher
    encryptor = cipher.encryptor() # Creates encryptor
    result = encryptor.update(padded_key) + encryptor.finalize() # Encrypts the OTP key
    result = binascii.hexlify(result) # Changes binary result back to hex
    result = result.decode("utf-8") # Decodes the utf-8 encoding to display the ciphertext
    passwordHash = str(bcrypt.hashpw("cs370".encode("utf-8"), salt)) # Hashes the password

    f = open("secret.txt", "w") # Opens secret.txt
    f.write(result + "\n") # Writes the encrypted OTP key
    f.write(passwordHash) # Writes the hashed password
    f.close() # Closes secret.txt
    print("QR Code generated successfully in qrcode.jpg")

def getOTP(key):
    key = base64.b32decode(key, True) # Decodes key (result is a bytes object)
    tx = time.time() # Gets current UNIX time
    tCounter = int(tx // 30) # Integer division by 30 sec time interval
    tCounter = struct.pack(">Q", tCounter) # Packs tCounter into a bytes object
    hashFunc = hashlib.sha1 # Uses SHA1 as encryption for TOTP
    hmacGenerator = hmac.new(key, tCounter, hashFunc)
    result = bytearray(hmacGenerator.digest()) # Generates hash
    offset = result[-1] & 15 # Takes last byte to generate offset
    # Creates a 31-bit integer and mods it to a 6-digit number
    result = str((struct.unpack(">I", result[offset:offset+4])[0] & 0x7fffffff) % 1000000)
    while len(result) < 6:
        result = "0" + result # Pads with 0s at the beginning of the number if needed
    return result


# Main Function
if (sys.argv[1] == "--generate-qr"): # If QR generation argument is passes
    makeQRCode()
elif (sys.argv[1] == "--get-otp"): # If get OTP argument is passed
    try:
        f = open("secret.txt", 'r') 
    except FileNotFoundError as e:
        print(f"File containing secret key (secret.txt) not found.", file=sys.stderr)
        exit()
    lines = f.readlines() # Reads contents of secret.txt
    for i in range(0,2):
        if i == 0:
            encryptedKey = lines[0].strip() # Encrypted OTP key is first line
        if i == 1:
            pwordHash = lines[1].strip() # Hashed password is second line
    f.close()

    # Takes a password from the user, hashes it, and if the same hash as the stored hashed
    # password is obtained, continues the program
    triedPassword = input("Please enter the password (it's just 'cs370'): ").strip()
    triedPasswordHash = str(bcrypt.hashpw(triedPassword.encode("utf-8"), salt))
    if triedPasswordHash == pwordHash:
        print("Password accepted.")
        cipher = Cipher(algorithms.AES(storageKey.encode()), modes.ECB()) # Creates cipher object
        decrypt = cipher.decryptor() # Creates decryptor
        key = decrypt.update(binascii.unhexlify(encryptedKey.encode())) + decrypt.finalize() # Decrypts OTP key
        key = key.decode()[0:16] # Key should be 16 digits
        while True:
            totp = getOTP(key) # Gets TOTP
            t = int(time.time()) % 30 # Calculates how long the TOTP is valid for
            print("Passcode " + totp + " valid for " + str(30 - t) + " seconds.")
            time.sleep(1)
    else:
        print("Password not accepted. Exiting program.")
else:
    print("Incorrect arguments entered.\nEither '--generate-qr' or '--getotp' must be specified.")