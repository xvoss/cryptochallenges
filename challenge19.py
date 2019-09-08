"""
Set 3: Break fixed-nonce CTR mode using substitutions

The strategy is to look at the first n'th bytes of each encrypted text and
guess the byte, the one with the most english characters is the byte of the
keystream.

The point of this exercise was not to develop and automatic script, but to
play around with swapping bytes to see the vulnerability in nonce re-use.
"""
import base64
import challenge18

KEY = b'\xee\x9bJ\x8d\x10h+\xe6\xd0\xb1\xfc\xfdW\x90&l'


def generate_ciphertexts(key, strings):
    ctexts = []
    cipher = challenge18.AES_CTR(key, 0x0, 16, inc=False)
    for s in strings:
        ctexts.append(cipher.encrypt(s))

    return ctexts


def finde(text):
    for b in text:
        if b == 101:
            print(chr(b), end='')

def main():
    global KEY
    plaintexts = []
    with open("data/19.txt", "r") as fd:
        for line in fd:
            plaintexts.append(base64.b64decode(line.rstrip()))

    ciphertexts = generate_ciphertexts(KEY, plaintexts)

    col = []
    for c in ciphertexts:
        col.append(c[4])

    for i in range(0, 256):
        print("BYTE", i)
        for b in col:
            print(chr(b ^ i), end="")
        print("\n")
    # above loop allows us to spot the byte with most english characters

    stream = [110, 250, 191, 235]
    #steam2 = [110, [221, 218], ]

    for c in ciphertexts:
        prefix = []
        for b1, b2 in zip(stream, c):
            prefix.append(b1 ^ b2)
        print(bytes(prefix).decode())

    # and on and on...


if __name__ == '__main__':
    main()
