"""
Set 2: Byte-at-a-time ECB decryption (simple)

Decrypt unknown text where it is appended, then encrypted, to any text we give
i.e. a server that uses: AES_ECB(attacker_text || unknown text).

How to decrypt the unknown text?
Assuming the server has a constant key and it uses AES_ECB, every plaintext
block will always map to the same ciphertext block. This means we can guess
the plaintext block and see if it matches the real cipher blocks. First, we
send text with blocksize-1 arbitrary bytes (let this be called PAD), so the
last byte of the block is the first unknown byte, lets call this A. Then we
save A and add every possible byte, someByte, to the end of PAD. We send PAD +
someByte and if the encrypted block matches A, the we know that someByte is
the unknown byte. To continue, PAD's ending is removed (to shift unknown
characters into PAD) and that is compared to PAD + decrypted bytes + someByte
until the entire block is decrypted. To move to the next blocks, we look only
at the next 16 bytes and use the last 15 decrypted bytes for PAD while
repeating the process described.
"""
import struct
import socket


class EcbCrackerSimple():
    """
    Break any encryption of the form: AES_ECB(attacker_text || unknown text)
    i.e. AES in ecb mode that appends unknown text after text we control.

    First, we check that the oracle uses AES in ECB mode and the block size.
    Then, the decryption is initalized, encrypting with added bytes, saving the
    relevant block of cipher text and then bruteforcing the end byte to match
    that block. This is repeated for each byte.

    :param oracle: speak to server and get ciphertext via oracle.encrypt(...)
    :param chars: (lowerbound, upperbound) range of bytes for bruteforcing
    """
    def __init__(self, oracle, chars):
        self._oracle = oracle
        self._chars = chars
        self._blocksize = None
        self.plaintext = b""

    def _is_ecb(self):
        """
        Confirm oracle uses ECB mode for AES encryption while finding the
        blocksize. for each block size if the first block is the same as the
        rest, then we know it is ecb and thats the block size.
        :return: (if oracle uses ecb, block size)
        """
        # assume block size are powers of 2 and <= 2 ^ 10
        size = 2
        prev_block = None
        flag = True
        while size <= 1024:

            # 40 blocks of block size
            msg = b"A" * size * 40
            ctext = self._encrypt(msg)

            cblocks = [ctext[i:i+size] for i in range(0, len(ctext), size)]
            for block in cblocks[:40]:
                if cblocks[0] != block:
                    flag = False
                    break

            if flag:
                return (True, size)

            size *= 2
            flag = True

        return (False, None)

    def start(self):
        ecb, bsize = self._is_ecb()
        if ecb:
            self._blocksize = bsize
            print("block chain mode is ECB")
            print("block size = {}".format(self._blocksize))
        else:
            raise ValueError("[*] is_ecb did not detect ECB in oracle.")

        self._decrypt(0)

    def _decrypt(self, start):
        """
        Adds the appropriate amount of padding to plaintext and saves the
        encrypted target block from the oracle, so the end byte can be
        bruteforced.

        :start: start decryption from block index start and forward
        TODO: It would be elegant to remove if statements when i = 0, no
        padding is necessary. Also use modulo instead of iteration?
        """
        n = start
        while True:
            for i in range(self._blocksize)[::-1]:

                if i != 0:
                    msg = (b"A" * i)
                else:
                    msg = (b"A" * self._blocksize)

                ctext = self._encrypt(msg)
                if n > len(ctext):
                    return True

                if i != 0:
                    trueblock = ctext[n:n + self._blocksize]
                else:
                    n += self._blocksize
                    trueblock = ctext[n:n + self._blocksize]
                    n -= self._blocksize

                matrix = self._bruteforce(i, n)
                if trueblock in matrix.keys():
                    old_text = list(self.plaintext)
                    old_text.append(matrix[trueblock])
                    self.plaintext = bytes(old_text)
                else:
                    return False

            n += self._blocksize

    def _bruteforce(self, index, block):
        """
        Adds every possible character to plaintext block and encrypts it.

        :return matrix: dictionary of possible encrypted blocks given
        self._chars range. {character: encrypted block}
        """
        lowerbound, upperbound = self._chars[0], self._chars[1]
        matrix = {}
        for b in range(lowerbound, upperbound, 1):
            new_text = list(b"A" * index + self.plaintext)
            new_text.append(b)
            ctext = self._encrypt((bytes(new_text)))
            guess = ctext[block:block + self._blocksize]
            matrix[guess] = b

        return matrix

    def _encrypt(self, text):
        """
        Wrapper for communicating with server. Override this function if
        padding needs to be added to text without affecting algorithm
        """
        return self._oracle.send(text)


class OracleClient():
    """
    Communication between the decryption algorithm and the oracle server

    :param host: IP of encryption server
    :param port: port of encryption server
    """
    def __init__(self, host, port):
        self._host = host
        self._port = port

    def send(self, msg):
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.connect((self._host, self._port))
        self._s.send(msg)
        header = self._s.recv(4)
        csize = struct.unpack("I", header)[0]
        ciphertext = self._s.recv(csize)
        self._s.close()

        return ciphertext


def main():
    oracle = OracleClient("127.0.0.1", 4444)

    characters = (0, 2 ** 7)
    cracker = EcbCrackerSimple(oracle, characters)
    cracker.start()
    print("[*] Detected Plaintext:\n")
    print(cracker.plaintext.decode('ascii'))


if __name__ == '__main__':
    main()
