import challenge18 #CTR encryption
import struct
import base64
import os


class CTR_API(challenge18.AES_CTR):
    def __init__(self, key, nonce):
        super().__init__(key, nonce, 16)


    def edit(self, ciphertext, offset, plaintext):
        """
        API call the attacker controls
        """
        count, pos = offset // 16, offset % 16

        form = struct.pack("Q", self._nonce) + struct.pack("Q", count)
        print("DECRYPT", form)
        keystream = self._cipher.encrypt(form)

        ciphertext[offset] = plaintext ^ keystream[pos]



def main():
    KEY = os.urandom(16)
    NONCE = 0x0
    entext = ""
    with open("data/25.txt", "r") as fd:
        for line in fd:
            entext += line.rstrip()

    plaintext = base64.b64decode(entext)
    api = CTR_API(KEY, NONCE)
    ciphertext = bytearray(api.encrypt(plaintext))


    decrypted = []
    for offset in range(len(ciphertext)):
        cipherbyte = ciphertext[offset]

        #for byte in range(0, 257):
            #assert(byte != 256)
        api.edit(ciphertext, offset, 0x22)
        new = ciphertext[offset]
        stream =  new ^ 0x22
        p = stream ^ cipherbyte
        decrypted.append(p)


    #print(bytes(decrypted))

    print(len(ciphertext))


if __name__ == '__main__':
    main()
