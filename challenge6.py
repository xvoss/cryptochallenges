"""
set1: Break repeating-key XOR
python challenge6.py 3
"""
import sys
import base64
import challenge3
import challenge5

class VigenereKeySize():
    """NOTE possible bug: list not in bytes() """
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
        ctext_blocks = [self.__ctext[i:i+keysize]
                        for i in range(0, len(self.__ctext), keysize)]
        distances = 0
        for _ in range(self.__rounds):
            if len(ctext_blocks) < 2:
                raise ValueError("Too many rounds: not enough blocks in ciphertext")
            distances += self.__hamming_dist(ctext_blocks[0], ctext_blocks[1])
            ctext_blocks.pop(0)

        return (distances / self.__rounds) / keysize

    def __hamming_dist(self, s1, s2):
        """ Peter Wegner: A technique for counting ones in a binary computer """
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
