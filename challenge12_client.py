"""
Set 2: Byte-at-a-time ECB decryption (simple)
"""
import struct
import socket

class EcbCrackerSimple():
    """
    Break any encryption of the form: AES_ECB(attacker_text || unknown text)
    i.e. AES in ecb mode that appends unknown text after text we control.

    First, we check that the oracle uses AES in ECB mode and the block size.
    Then, the decryption is initalized, encrypting padding, saving the
    relevant block of cipher text and then bruteforcing the end byte to match
    that block. This is repeated for each byte.

    :param oracle: any class that encrypts text upon oracle.encrypt(...) call
    :param chars: (lowerbound, upperbound) range of bytes for bruteforcing
    """
    def __init__(self, oracle, chars):
        self.__oracle = oracle
        self.__chars = chars
        self.__blocksize = None
        self.plaintext = b""

    def __is_ecb(self):
        """
        Confirm oracle uses ECB mode for AES encryption while finding the
        blocksize. for each block size if the first block is the same as the
        rest, then we know it is ecb and thats the block size.
        :return: (if oracle uses ecb, and block size)
        """
        # assume block size are powers of 2 and <= 2 ^ 10
        size = 2
        prev_block = None
        flag = True
        while size <= 1024:

            # 40 blocks of block size
            msg = b"A" * size * 40
            ctext = self.__oracle.encrypt(msg)

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
        ecb, bsize = self.__is_ecb()
        if ecb:
            self.__blocksize = bsize
            print("block chain mode is ECB")
            print("block size = {}".format(self.__blocksize))
        else:
            raise ValueError("[*] is_ecb did not detect ECB in oracle.")

        self.__decrypt()


    def __decrypt(self):
        """
        TODO: It would be elegant to remove if statements when i = 0, no
        padding is necessary
        """
        n = 0
        while True:
            for i in range(self.__blocksize)[::-1]:

                if i != 0:
                    msg = (b"A" * i)
                else:
                    msg = (b"A" * self.__blocksize)

                ctext = self.__oracle.encrypt(msg)
                if n > len(ctext):
                    return True

                if i != 0:
                    trueblock = ctext[n:n + self.__blocksize]
                else:
                    n += self.__blocksize
                    trueblock = ctext[n:n + self.__blocksize]
                    n -= self.__blocksize

                matrix = self.__bruteforce(i, n)
                if trueblock in matrix.keys():
                    old_text = list(self.plaintext)
                    old_text.append(matrix[trueblock])
                    self.plaintext = bytes(old_text)
                else:
                    return False

            n += self.__blocksize

    def __bruteforce(self, index, block):
        lowerbound, upperbound = self.__chars[0], self.__chars[1]
        matrix = {}
        for b in range(lowerbound, upperbound, 1):
            new_text = list(b"A" * index + self.plaintext)
            new_text.append(b)
            ctext = self.__oracle.encrypt((bytes(new_text)))
            guess = ctext[block:block + self.__blocksize]
            matrix[guess] = b

        return matrix


class OracleClient():
    """
    Communication between the decryption algorithm and the oracle server

    :param host: IP of encryption server
    :param port: port of encryption server
    """
    def __init__(self, host, port):
        self.__host = host
        self.__port = port

    def encrypt(self, msg):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__s.connect((self.__host, self.__port))
        self.__s.send(msg)
        header = self.__s.recv(4)
        csize = struct.unpack("I", header)[0]
        ciphertext = self.__s.recv(csize)
        self.__s.close()

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
