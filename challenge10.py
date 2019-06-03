"""
Set 2: Implement CBC mode

"""

import base64
from Crypto.Cipher import AES
from challenge5 import xor
from challenge9 import pkcs7_pad


class AES_CBC():
    def __init__(self, key, IV):
        self.__IV = IV
        self.__bsize = len(key)
        self.__cipher = AES.new(key, AES.MODE_ECB)
        assert(self.__bsize == 16)

    def encrypt(self, text):
        ciphertext = []
        plaintext = [text[i:i+self.__bsize]
                     for i in range(0, len(text), self.__bsize)]

        if len(plaintext[0]) != self.__bsize:
            plaintext[0] = pkcs7_pad(plaintext[0], self.__bsize)

        block = xor(plaintext[0], self.__IV)
        ciphertext.append(self.__cipher.encrypt(block))

        for p in plaintext[1:]:
            if len(p) != self.__bsize:
                p = pkcs7_pad(p, self.__bsize)

            block = xor(p, ciphertext[-1])
            ciphertext.append(self.__cipher.encrypt(block))

        output = b""
        for c in ciphertext:
            output += c

        return output

    def decrypt(self, text):
        plaintext = b""
        ciphertext = [text[i:i+self.__bsize]
                      for i in range(0, len(text), self.__bsize)]

        while len(ciphertext) > 1:
            block = self.__cipher.decrypt(ciphertext.pop())
            plaintext = xor(block, ciphertext[-1]) + plaintext

        block = self.__cipher.decrypt(ciphertext.pop())
        plaintext = xor(block, self.__IV) + plaintext

        return plaintext


def main():
    # encrypt and decrypt to ensure algorithm works both ways
    input1 = b"Lorem ipsum dolor sit amet, consectetur adipisci"
    cipher = AES_CBC(b"YELLOW SUBMARINE", b"\x55" * 16)
    output1 = cipher.encrypt(input1)
    assert(cipher.decrypt(output1) == input1)

    input2_b64 = ""
    with open("data/10.txt", "r") as file1:
        for line in file1:
            input2_b64 += line.rstrip()

    input2 = base64.b64decode(input2_b64)

    cipher = AES_CBC(b"YELLOW SUBMARINE", b"\x00" * 16)
    output2 = cipher.decrypt(input2)


if __name__ == '__main__':
    main()
