"""
set1: Single-byte XOR cipher
decrypt a xor'd line of text by bruteforcing each possible byte it may have
been xor'd with

Note: for all my code variables with the name 'key' refers to cryptographic
keys not dictionary keys.
"""
import binascii


class XorKeyScores():
    """
    Store and rank every possible decryption key by the frequency of english
    characters in that text. The resulting data structure is a stack where the
    top element is the highest english frequency and the corresponding key

    :param ctext: cipher text with single byte XOR cipher
    :param key_score: map in the form frequency score: key
    :param keys: list of bytes of all possible keys to try
    """
    def __init__(self, ctext, keys):
        self.ctext = ctext
        self.key_score = dict()

        for k in keys:
            test_text = self.xor_byte(self.ctext, k)
            self.key_score[self.freq_score(test_text)] = k

    def xor_byte(self, cbytes, byte):
        return bytes([b ^ byte for b in cbytes])

    def freq_score(self, cbytes):
        """
        Score string of bytes by the amount of common english characters it
        contains. This is determined using a histogram of the english alphabet
        """
        freq = {
            'E': 12.02, 'T': 9.1, 'A': 8.12, 'O': 7.68, 'I': 7.31, 'N': 6.95,
            'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32, 'L': 3.98, 'U': 2.88,
            'C': 2.71, 'M': 2.61, 'F': 2.3, 'Y': 2.11, 'W': 2.09, 'G': 2.03,
            'P': 0.82, 'B': 1.49, 'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11,
            'J': 0.1, 'Z': 0.07, ' ': 20}
        score = 0
        for m in cbytes:
            # in acscii range of letters
            if (m > 0x61 and m < 0x7a) or (m < 0x5a and m > 0x41) or m == 0x20:
                score += freq[chr(m).upper()]

        return score

    def peek_score(self):
        high_score = max(self.key_score.keys())
        key = self.key_score[high_score]
        return high_score

    def pop_key(self):
        """
        return key value with decrypted text that had the most common english
        characters
        """
        high_score = max(self.key_score.keys())
        key = self.key_score[high_score]
        del self.key_score[high_score]
        return high_score, key

    def to_text(self, key):
        return self.xor_byte(self.ctext, key).decode()


def main():
    # test ctext given
    input1 = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a" \
             b"393b3736"

    keys = [byte for byte in range(2 ** 7)]
    bruteforce = XorKeyScores(binascii.unhexlify(input1), keys)

    score, key = bruteforce.pop_key()

    print("[*] Most likely key: 0x{:02x}".format(key))
    print("[*] Decrypted Text: {}".format(bruteforce.to_text(key)))


if __name__ == '__main__':
    main()
