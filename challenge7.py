"""
set 1: AES in EBC mode

Test for encrypting texts in AES
"""
from Crypto.Cipher import AES
import base64


def main():
    KEY = b"YELLOW SUBMARINE"

    ctextb64 = ""
    with open("data/7.txt", "r") as file1:
        for line in file1:
            ctextb64 += line.rstrip()

    ctext = base64.b64decode(ctextb64)

    cipher = AES.new(KEY, AES.MODE_ECB)
    ptext = cipher.decrypt(ctext)

    print("[*] Decrypted text: ")
    print(ptext.decode('ascii'))

if __name__ == '__main__':
    main()
