"""
Set 3: Break fixed-nonce CTR mode using substitutions

The goal of this challenge is break encrypted text under CTR, when the nonce
remains constant, which is big implementation mistake. The encryption can be
broken as if it were a repeating XOR key cipher.

Lesson learned: Ensure the nonce to ciphers are random and not to a set value.
"""

import base64
import challenge18
import challenge19
import challenge6

KEY = b'\x1c~~\xaa+\x881\xa49\x0f\x82\xaa\x0f\x8c/\xb1'

def main():
    global KEY
    plaintexts = []
    with open("data/20.txt", "r") as fd:
        for line in fd:
            plaintexts.append(base64.b64decode(line.rstrip()))

    ciphertexts = challenge19.generate_ciphertexts(KEY, plaintexts)

    chain = bytes()
    for c in ciphertexts:
        chain += c[:16]

    keys = [i for i in range(0, 256)]
    key_finder = challenge6.VigenereKeys(chain, keys, 16)
    key_finder.gen_key()
    STREAM = key_finder.get_key()

    print("[*] DETECTED STREAMCIPHER:")
    print(STREAM)
    print("\n[*] DETECTED CIPHERTEXTS:")
    for ctext in ciphertexts:
        ptext = []
        for i, b in enumerate(ctext):
            ptext.append(STREAM[i % 16] ^ b)

        print(bytes(ptext))


if __name__ == '__main__':
    main()
