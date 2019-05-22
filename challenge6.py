"""
set1: Break repeating-key XOR
"""
import base64
import challenge3
import challenge5

class VigenereKeySize():
    """NOTE possible bug: list not in bytes() """
    def __init__(self, ctext, lower_bound=2, upper_bound=40, rounds=3):
        self.ctext = ctext
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound
        self.rounds = rounds
        self.keysizes = {}

        for k in range(lower_bound, upper_bound + 1):
            distance = self.avg_key_dist(k)
            keysizes[distance] = k

    def avg_key_dist(self, keysize):
        ctext_blocks = [self.ctext[i:i+keysize]
                        for i in range(0, len(self.ctext), keysize)]
        distances = 0
        for _ in range(self.rounds):
            distances += hamming_dist(ctext_blocks[0], ctext_blocks[1])
            if not ctext_blocks:
                raise ValueError("Too many rounds: not enough blocks in ciphertext")
            ctext_blocks.pop(0)

        return (distances / self.rounds) / keysize

    def hamming_dist(self, s1, s2):
        """ Peter Wegner: A technique for counting ones in a binary computer """
        count = 0
        for c1, c2 in zip(s1, s2):
            diff = c1 ^ c2
            while diff:
                count += 1
                diff &= diff - 1

        return count

    def pop(self):
        least_distance = min(self.keysizes.keys())
        size = self.keysizes[least_distance]
        del self.keysizes[least_distance]
        return least_distance, size


class VigenereKeys():
    def __init__(self, ctext, keyspace, keysize):
        self.ctext = ctext
        self.keyspace = keyspace
        self.keysize = keysize
        self.blocks = []
        self.key = []

        for t in transpose_txt():
            blocks.append(challenge3.XorKeyScores(t, self.keyspace))

    def transpose_txt(self):
        blocks = [list() for _ in range(self.keysize)]
        for i, byte in enumerate(self.ctext):
            blocks[i % self.keysize].append(byte)
        return [bytes(b) for b in blocks]

    def gen_key(self):
        self.key = []
        for b in blocks:
            score, byte = b.pop_key()
            self.key.append(byte)

    def to_text(self):
        



def main():
    ctext64 = ""
    with open("data/6.txt", "r") as file1:
        for line in file1:
            ctext64 += line.rstrip()

    print(base64.b64decode(ctext64))


if __name__ == '__main__':
    main()
#t1 = b"this is a test"
#t2 = b"wokka wokka!!!"
#assert(hamming_dist(t1, t2) == 37)
