"""
set1: challenge 3
decrypt a xor'd line of text by bruteforce each possible byte it may have been
xor'd with
"""
import binascii


class XorPlainText():
    """
    Represents a string XOR'd by every character (0 to 127) and its likely-
    ness to be plain english.

    :param cipherhex: an XOR'd string in hexstring form to be decrypted
    :param plaintexts: map in the form frequency score: decrypted text
    """
    def __init__(self, cipherhex):
        self.ciphertext = binascii.unhexlify(cipherhex)
        self.plaintexts = dict()

        for byte in range(2 ** 7):
            test_text = self.xor_byte(self.ciphertext, byte)
            self.plaintexts[self.freq_score(test_text)] = test_text

    def xor_byte(self, cbytes, byte):
        return bytes([b ^ byte for b in cbytes])

    def freq_score(self, cbytes):
        """
        Text scores are determined by letter frequency in the english alphabet
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

    def pop(self):
        key = max(self.plaintexts.keys())
        text = self.plaintexts[key]
        del self.plaintexts[key]
        return text


def main():
    # test ciphertext given
    input1 = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a" \
             b"393b3736"

    test = XorPlainText(input1)
    print("[*] Most likely text:\n{}".format(test.pop()))


if __name__ == '__main__':
    main()
