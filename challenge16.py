"""
Set 2: CBC bitflipping attacks

NOTE: For this challenge an oracle was not implemented ...
"""

import os
import re
from Crypto.Cipher import AES
from challenge9 import pkcs7_pad

class Oracle():
    def __init__(self, cipher, prefix, postfix):
        self._cipher = cipher
        self._prefix = prefix
        self._postfix = postfix

    def encrypt(self, plaintext):
        # prevent user from creating a ;admin=true; string
        plaintext.replace(b";", b"")
        plaintext.replace(b"=", b"")
        plaintext.replace(b"&", b"")
        text = self._prefix + plaintext + self._postfix

        return self._cipher.encrypt(pkcs7_pad(text, 16))

    def create_account(self, ciphertext):
        text = self._cipher.decrypt(ciphertext)
        if b";admin=true;" in text:
            return True
        else:
            return False


def main():
    KEY = os.urandom(16)
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)

    prefix = b"comment1=cooking%20MCs;userdata="
    postfix = b";comment2=%20like%20a%20pound%20of%20bacon"

    oracle = Oracle(cipher, prefix, postfix)

    payload = b"ZadminZtrueZ"

    # ensure payload is in its own block
    rem = len(prefix) % 16
    if rem != 0:
        padding = 16 - rem
    else:
        padding = 0

    payload = b"A" * padding + payload
    # ciphertext index that must be corrupted i.e. before payload
    n = 1

    ctext = oracle.encrypt(payload)
    cblocks = [ctext[n:n+16] for n in range(0, len(ctext), 16)]

    corrupt = bytearray(cblocks[n])
    corrupt[0] ^= ord("Z") ^ ord(";")
    corrupt[6] ^= ord("Z") ^ ord("=")
    corrupt[11] ^= ord("Z") ^ ord(";")

    cblocks[n] = bytes(corrupt)
    ctext = b''.join(cblocks)

    assert(oracle.create_account(bytes(ctext)) == True)
    print("[*] Admin account created")


if __name__ == '__main__':
    main()
