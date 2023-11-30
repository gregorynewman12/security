import struct
import qrcode
import sys
import time
import base64
import hashlib
import hmac
import os


def makeQRCode():
    key = base64.b32encode(os.urandom(10))
    uri = "otpauth://totp/Gregory:newmangr?secret=" + key.decode() + "&issuer=Gregory"
    qrcode.make(uri).save("qrcode.jpg")
    key = key.decode()
    f = open("secret.txt", "w")
    f.write(key)
    f.close()
    print("QR Code generated successfully in qrcode.jpg")
    print("Key is: [" + key + "]")

def getOTP(key):
    key = base64.b32decode(key, True)
    tx = time.time() # Gets current UNIX time
    tCounter = int(tx // 30) # Integer division by 30 sec time interval
    tCounter = struct.pack(">Q", tCounter)
    hashFunc = hashlib.sha1
    hmacGenerator = hmac.new(key, tCounter, hashFunc)
    result = bytearray(hmacGenerator.digest()) # Generates hash
    offset = result[-1] & 15 # Takes last byte to generate offset
    result = str((struct.unpack(">I", result[offset:offset+4])[0] & 0x7fffffff) % 1000000)
    while len(result) < 6:
        result = "0" + result
    return result


# Main Function
if (sys.argv[1] == "--generate-qr"):
    makeQRCode()
elif (sys.argv[1] == "--get-otp"):
    try:
        f = open("secret.txt", 'r') 
    except FileNotFoundError as e:
        print(f"File containing secret key (secret.txt) not found.", file=sys.stderr)
        exit()
    key = f.readline()
    f.close()
    lastTOTP = 0
    while True:
        totp = getOTP(key)
        if totp != lastTOTP:
            print("Passcode " + totp + " valid for 30 seconds.")
            lastTOTP = totp
            time.sleep(1)
else:
    print("Incorrect arguments entered.\nEither '--generate-qr' or '--getotp' must be specified.")