"""
set1: Break repeating-key XOR
$ python challenge6.py 3

This script cracks the key for a repeating-key XOR cipher or "Vigenere"
cipher. The process, which was provided by cryptopals the challenge maker,
goes as following:

Step 1: The best keys will be the ones that have the lowest hamming distances
per length. For each key size, take the first and second key size blocks of
the cipher text and find the hamming distance between them.
Step 2: For each of the best three key sizes attempt to find the key with the
next steps...
Step 3: Transpose the cipher text. For each block (key size of bytes)
take the first elements and put that in an array, take each second element and
put those in an array, and so on...
Step 4: Each transposed block is then solved for as if it was a
single-character XOR cipher. This was done in challenge 3.
Step 5: The key that generates an english plain text is the correct key
"""
import sys
import base64
import challenge3
import challenge5


class VigenereKeySize():
    """
    Stack that holds possible key sizes of a repeating-key XOR'd cipher text
    The top elements contains the key size with the lowest hamming distance
    (normalized by keysize).

    :param ctext: cipher text with reapeating-key XOR cipher
    :param lower_bound: smallest key size possibly used
    :param upper_bound: largest key size possibly used
    :param rounds: amount of hamming distances to calculate for each key size
    :param keysizes: store the hamming distance and the respective key
    """
    def __init__(self, ctext, lower_bound=2, upper_bound=40, rounds=3):
        self.__ctext = ctext
        self.__lower_bound = lower_bound
        self.__upper_bound = upper_bound
        self.__rounds = rounds
        self.__keysizes = {}

        for k in range(lower_bound, upper_bound + 1):
            distance = self.__avg_key_dist(k)
            self.__keysizes[distance] = k

    def __avg_key_dist(self, keysize):
        """
        hamming distance (per key size) of cipher text for each key size
        """
        ctext_blocks = [self.__ctext[i:i+keysize]
                        for i in range(0, len(self.__ctext), keysize)]
        distances = 0
        for _ in range(self.__rounds):
            if len(ctext_blocks) < 2:
                raise ValueError("Too many rounds:"
                                 "not enough blocks in ciphertext")
            distances += self.__hamming_dist(ctext_blocks[0], ctext_blocks[1])
            ctext_blocks.pop(0)

        return (distances / self.__rounds) / keysize

    def __hamming_dist(self, s1, s2):
        """
        Hamming distance between to strings of bytes
        technique for calculating hamming distance can be found in:
        Peter Wegner: A technique for counting ones in a binary computer
        """
        count = 0
        for c1, c2 in zip(s1, s2):
            diff = c1 ^ c2
            while diff:
                count += 1
                diff &= diff - 1

        return count

    def pop(self):
        least_distance = min(self.__keysizes.keys())
        size = self.__keysizes[least_distance]
        del self.__keysizes[least_distance]
        return least_distance, size


class VigenereKeys():
    """
    Crack the key for a repeating-key XOR cipher. The cipher text is
    transposed and each block is solved for as a single-character XOR cipher.

    :param ctext: cipher text
    :param keyspace: possible single-character byte keys for each block
    :param keysize: the size of key or block size of cipher text
    :param blocks: transposed cipher text, where each element has a common
    single-character key
    :param key: Final key resulting from each bruteforced block
    """
    def __init__(self, ctext, keyspace, keysize):
        self.__ctext = ctext
        self.__keyspace = keyspace
        self.__keysize = keysize
        self.__blocks = []
        self.__key = bytes()

        for t in self.__transpose_txt():
            self.__blocks.append(challenge3.XorKeyScores(t, self.__keyspace))

    def __transpose_txt(self):
        blocks = [list() for _ in range(self.__keysize)]
        for i, byte in enumerate(self.__ctext):
            blocks[i % self.__keysize].append(byte)
        return [bytes(b) for b in blocks]

    def gen_key(self):
        chars = []
        for b in self.__blocks:
            score, byte = b.pop_key()
            chars.append(byte)

        self.__key = bytes(chars)

    def get_ptext(self):
        return challenge5.xor(self.__ctext, self.__key)

    def get_key(self):
        return self.__key


def main():
    if len(sys.argv) != 2:
        print("Usage: {} [keys to try]".format(sys.argv[0]))
        sys.exit()

    # amount of keys to try from hamming distance calculation
    ATTEMPTS = int(sys.argv[1])

    ctextb64 = ""
    with open("data/6.txt", "r") as file1:
        for line in file1:
            ctextb64 += line.rstrip()

    ctext = base64.b64decode(ctextb64)

    key_lengths = VigenereKeySize(ctext)

    solutions = []
    chars = [k for k in range(2 ** 7)]
    for _ in range(ATTEMPTS):
        distance, length = key_lengths.pop()
        solutions.append(VigenereKeys(ctext, chars, length))

    for s in solutions:
        s.gen_key()
        print("[*] KEY: {}".format(s.get_key()))
        print("[*] Plain Text: {}".format(s.get_ptext()))
        print("\n\n")


if __name__ == '__main__':
    main()
