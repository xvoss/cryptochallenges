"""
Set 4: Recover the key from CBC with IV=Key

Setting the IV the same as the key can lead to vulnerabilities. In this case,
when the plaintext is given back, and the ciphertext can be manipulated.

Suppose three blocks are encrypted. The ciphertext can be changed as follows:
C0, C1, C2 = C0, 0, C0
Then when the plaintexts are given back:
key = P'0 XOR P'2

Technical Explanation:
We want the IV, and C0 contains the IV it is E(P0 XOR IV). So we place C0 at
the end to decrypt it, and it is XOR'd by the previous block (we changed to 0)
So what is left is P0 XOR IV decrypted as P'2. So lastly we XOR P'2 and P'0 to
eliminate P0 and get the IV.

Lesson:
Don't use the IV as key, make sure it is truely random. Typically it is good
practice not to reuse values in crypto.

"""
import os
import binascii
import challenge16
import challenge2
from Crypto.Cipher import AES


class AsciiOracle(challenge16.Oracle):
    def __init__(self, key):
        self._key = key
        prefix = b"userdata="
        postfix = b";comment2=bacon"
        cipher = AES.new(key, AES.MODE_CBC, key)
        super().__init__(cipher, prefix, postfix)

    def decrypt(self, ciphertext):
        """
        For some reason one cipher object cannot decrypt and encrypt, so a new
        one is created
        """
        cipher = AES.new(self._key, AES.MODE_CBC, self._key)
        plaintext = cipher.decrypt(ciphertext)

        flag = False
        for byte in list(plaintext):
            if byte > 0x7e or byte < 0x07:
                flag = True

        if flag:
            print("[*] Error: message contains non-ASCII character!")

        return plaintext



def main():
    BLOCK = 3
    key = os.urandom(16)
    oracle = AsciiOracle(key)

    # assume we know the oracle will add these to our text
    prefix = b"userdata="
    postfix = b";comment2=bacon"

    """ ATTACK """
    pad = BLOCK * 16 - (len(prefix) + len(postfix))
    message = b"A" * (pad - 1) # subtract one to prevent extra padding
    ciphertext = oracle.encrypt(message)

    c0 = ciphertext[:16]
    dummytext = c0 + b"\x00" * 16 + c0

    corrupt = oracle.decrypt(dummytext)
    iv = challenge2.xor(corrupt[:16], corrupt[-16:])

    print("[*] Recovered key:", binascii.hexlify(iv))


if __name__ == '__main__':
    main()
