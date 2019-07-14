"""
Set 2: CBC bitflipping attacks

Proof of concept demonstrating corrupting data encrypted under AES_CBC to
obtain priviledge escalation.

Overview:
The flaw comes from the fact that the attacker can manipulate the ciphertext
and thus the plaintext once decrypted. This is not due to the encryption
algorithm, AES, but rather the block chaining mode: CBC. In CBC, the plaintext
is obtained via XOR'ing the decrypted ciphertext block with the previous
ciphertext block. But the attacker can manipulate all ciphertext blocks right?
Yes, so the attacker replaces the previous cipherblock with the that
cipherblock XOR the current plaintext, and XOR with the target byte to be
injected. The previous ciphertext and the plaintext will be cancelled out
(B XOR B = 0) leaving the target byte in the plaintext during the XOR'ing
process.

In summary:
For every byte to be manipulated:
Let C be the byte in the previous block being targeted
Let P be the current plaintext byte
Let A be the arbitrary byte the attacker want's to insert

Set C = C XOR P XOR A
"""
import os
import re
from Crypto.Cipher import AES
from challenge9 import pkcs7_pad


class Oracle():
    """
    A 'server' that creates URL string, adding user's text, and returning the
    encrypted result

    :param cipher: encrypt algorithm, needs .encrypt(), and .decrypt() calls
    :param prefix: bytes(), text added before user's text
    :param postfix: bytes(), text added after user's text
    """
    def __init__(self, cipher, prefix, postfix):
        self._cipher = cipher
        self._prefix = prefix
        self._postfix = postfix

    def encrypt(self, plaintext):
        """
        Create URL string, adding prefix, postfix comments
        :return: encrypted URL result.
        """
        # prevent user from creating a ;admin=true; string
        plaintext.replace(b";", b"")
        plaintext.replace(b"=", b"")
        plaintext.replace(b"&", b"")
        text = self._prefix + plaintext + self._postfix

        return self._cipher.encrypt(pkcs7_pad(text, 16))

    def create_account(self, ciphertext):
        """
        Does plaintext contain admin=true? if so the client has defeated the
        crypto.
        """
        text = self._cipher.decrypt(ciphertext)
        if b";admin=true;" in text:
            return True
        else:
            return False


def main():
    KEY = os.urandom(16)
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)

    # mimic text added in a URL
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

    assert(oracle.create_account(bytes(ctext)))
    print("[*] Admin account created")


if __name__ == '__main__':
    main()
