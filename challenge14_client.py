"""
Set 2: Byte-at-a-time ECB decryption (Harder)
"""
import challenge12_client
from collections import Counter

class AES_ECB_Cracker_Hard(challenge12_client.EcbCrackerSimple):
    """
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
