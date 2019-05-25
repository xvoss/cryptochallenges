"""
set 1: Detect AES in ECB mode

Find a ECB ciphered text amoung other ciphered texts.
the solution would be to find the ciphertext whose blocks
repeat themselves the most since ECB encryption typically have repeating
blocks
"""
import binascii
from collections import Counter


def find_ecb_cipher(ctexts, bsize):
    """
    Find the most common block for each ctext and return the ctext that
    had the block with the highest frequency
    """
    rank = dict()
    for c in ctexts:
        blocks = [c[i:i+bsize] for i in range(0, len(c), bsize)]
        count = Counter(blocks)
        top = count.most_common()[0][1]
        rank[top] = c
    return rank[max(rank.keys())]


def main():
    ctexts = []
    with open("data/8.txt", "r") as file1:
        for line in file1:
            ctexts.append(binascii.unhexlify(line.rstrip()))

    ecb_text = find_ecb_cipher(ctexts, 16)
    lnum = ctexts.index(ecb_text)

    print("[*] Likely cipher text in ECB mode: {}".format(ecb_text))
    print("[*] Found at line {}".format(lnum))


if __name__ == '__main__':
    main()
