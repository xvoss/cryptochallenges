"""
Set 2: Byte-at-a-time ECB decryption (Harder)

Same as challenge 12, only that the oracle appends random amount of bytes
BEFORE our controlled text while still appending unknown text. i.e.
AES_ECB(random bytes || attacker text || unknown text)

We can just perform the previous attack with the excecption that we find
which block the attacker text is in and add padding before it, so it starts
at the beginning of a block.
"""
import challenge12_client
from collections import Counter


class AES_ECB_Cracker_Hard(challenge12_client.EcbCrackerSimple):
    """
    Decrypt bytes that are added after text we send to a server that encrypts
    under AES_ECB one byte-at-a-time. The difference between hard and simple
    is that this time the server also PREPENDS random amount of bytes before
    our text i.e. AES_ECB(random bytes || attacker text || unknown text).
    An added method is used to determine where attacker text is, and to add
    padding so that attacker text starts at the beginning of a block.

    :param oracle: class, Communicate with via .send(...) call
    :chars: (start, end) range of bytes from start to end, inclusive, to
    bruteforce

    NOTE: this algorithm assumes blocksize is 16
    TODO: add padding byte and blocksize to class variables
    """
    def __init__(self, oracle, chars):
        self._cpad = None
        super().__init__(oracle, chars)
        self._blocksize = 16

    def start(self):
        padding, entry = self._entry_point()
        self._cpad = padding * b"@"
        self._decrypt(entry)

    def _entry_point(self):
        """
        Determine where our text is contained with in ciphertext, as well as
        padding required to set text at start of a block.

        :return: (arbitrary bytes for padding, index by block of our text)
        """
        ctext = self._oracle.send(b"@")
        canary = b"@" * (len(ctext) + 32)
        ctext = self._oracle.send(canary)
        block = self._common_block(ctext)

        if not block:
            raise RuntimeError("entry_point: redundant block not detected."
                               "Is oracle using AES ECB mode?")

        probe = b"@" * 15
        ctext = b""
        index = -1
        while index < 0:
            probe += b"@"
            ctext = self._oracle.send(probe)
            index = ctext.find(block)

        padding = len(probe) - self._blocksize

        return (padding, index)

    def _common_block(self, ctext, percent=0.50):
        """
        :return: block, if any, that appears more than percent ratio
        """
        blocks = [ctext[i:i+self._blocksize]
                  for i in range(0, len(ctext), self._blocksize)]

        repeat, count = Counter(blocks).most_common(1)[0]
        occur = count / len(blocks)

        if occur >= percent:
            return repeat
        else:
            return None

    def _encrypt(self, text):
        """
        padding to set any text sent in the start of a block
        """
        return self._oracle.send(self._cpad + text)


def main():
    oracle = challenge12_client.OracleClient("127.0.0.1", 4444)
    characters = (0, 2 ** 7)
    cracker = AES_ECB_Cracker_Hard(oracle, characters)
    cracker.start()
    print("[*] Detected Plaintext:\n")
    print(cracker.plaintext.decode('ascii'))


if __name__ == '__main__':
    main()
