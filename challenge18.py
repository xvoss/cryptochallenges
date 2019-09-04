"""
Set 3: Implement CTR, the stream cipher mode
"""
from Crypto.Cipher import AES
import challenge2
import base64
import struct


class AES_CTR():
    def __init__(self, key, nonce, blocksize):
        self._key = key
        self._blocksize = blocksize
        self._nonce = nonce
        self._count = 0x0
        self._cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, msg):
        n = self._blocksize
        count = self._count
        ciphertext = b""

        blocks = [msg[i:i+n] for i in range(0, len(msg), n)]
        for b in blocks:
            #TODO FIX THIS FORMAT WHAT DOES AES ENCRYPT?
            form = struct.pack("Q", self._nonce) + struct.pack("Q", count)
            keystream = self._cipher.encrypt(form)
            count += 1

            if len(b) % n == 0:
                ciphertext += challenge2.xor(keystream, b)
            else:
                end = len(b)
                ciphertext += challenge2.xor(keystream[:end], b)

        return ciphertext

    def decrypt(self, msg):
        return self.encrypt(msg)


def main():
    unknown = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    raw = base64.b64decode(unknown)

    cipher = AES_CTR(b"YELLOW SUBMARINE", 0x0, 16)

    msg = cipher.decrypt(raw)
    print("[*] Decrypted Ciphertext:\n{}".format(msg.decode('utf-8')))


if __name__ == '__main__':
    main()