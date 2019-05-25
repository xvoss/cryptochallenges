"""
set1: Detect single-character XOR

"""

import binascii
import challenge3


def main():
    keys = [byte for byte in range(2 ** 7)]

    ciphers = []
    hexstrings = []
    with open("data/4.txt", "r") as texts:
        for line in texts:
            hexstrings.append(line.strip())
            c = challenge3.XorKeyScores(binascii.unhexlify(line.strip()), keys)
            ciphers.append(c)

    # most likely english text out of each individual XOR hexstring
    cipher_scores = {}
    for c in ciphers:
        rank = c.peek_score()
        cipher_scores[rank] = c

    top_rank = max(cipher_scores.keys())
    best_cipher = cipher_scores[top_rank]

    score, key = best_cipher.pop_key()
    print("[*] Most likely key: 0x{:02x}".format(key))
    print("[*] Decrypted Text: {}".format(best_cipher.to_text(key)))

if __name__ == '__main__':
    main()
