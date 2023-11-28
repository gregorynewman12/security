import qrcode
import sys
import time
import base64
import hashlib
import hmac


def makeQRCode():
    key = b"Giant steps in giant shoes"
    key = base64.b32encode(key)
    key = key[0:32] # Shortens the key to an appropriate length
    uri = "otpauth://totp/Gregory:newmangr?secret=" + key.decode() + "&issuer=Gregory"
    print("uri1: " + uri)
    qrcode.make(uri).save("qrcode.jpg")
    key = base64.b32decode(key)
    f = open("secret.txt", "w")
    f.write(key.decode())
    f.close()

def getOTP(key):
    tx = time.time() # Gets current UNIX time
    tCounter = tx // 30 # 
    tCounter = str(tCounter)
    hashFunc = hashlib.sha1

    hmacGenerator = hmac.new(key.encode(), tCounter.encode(), hashFunc)
    hexHash = str(hmacGenerator.hexdigest())
    # print(hexHash)
    lastChar = "0x" + str(hexHash[-1])
    lastChar = int(lastChar, 0)
    # print(lastChar)
    trunc = hexHash[lastChar:lastChar + 8]
    # print("Truncated value: ", trunc)
    trunc = int(trunc, 16)
    # print(trunc)
    totp = str(trunc)[0:6]
    # print("totp: " + totp)
    return totp


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

